<?php
declare(strict_types=1);
namespace RuRouting;
use RuntimeException;

function categoryNames(): array {
    return ['banks'=>'Банки и финансы','government'=>'Госуслуги','shops'=>'Магазины и доставка','technology'=>'Технологии и соцсети','media'=>'Медиа и спорт','travel'=>'Транспорт и путешествия','telecom'=>'Связь','education'=>'Образование','health'=>'Медицина','life'=>'Недвижимость, авто и работа','industry'=>'Промышленность','other'=>'Другие сервисы'];
}
function readCategories(string $source): array {
    $keys=array_keys(categoryNames()); $current='other'; $out=[];
    foreach (preg_split('/\r\n|\n|\r/', $source) as $line) {
        if (preg_match('/^#\s*(\d+)\./u', $line, $m)) { $current=$keys[(int)$m[1]-1] ?? throw new RuntimeException('Неизвестная категория'); continue; }
        if (str_starts_with($line, '# Дополнения')) { $current='other'; continue; }
        $line=trim(explode('#',$line,2)[0]); if ($line==='') continue;
        $host=domain($line); if (isset($out[$host]) && $out[$host]!==$current) throw new RuntimeException('Домен указан в разных категориях: '.$host);
        $out[$host]=$current;
    }
    return $out;
}
/** Parse only explicitly categorized, syntactically valid hosts from the fixed upstream. */
function upstreamCategories(string $source): array {
    $keys=array_keys(categoryNames()); $current=null; $out=[];
    foreach (preg_split('/\r\n|\n|\r/', $source) as $line) {
        if (preg_match('/^#\s*(\d+)\./u', $line, $m)) { $current=$keys[(int)$m[1]-1] ?? null; continue; }
        $name=trim(explode('#',$line,2)[0]); if ($current===null || $name==='') continue;
        try { $host=domain($name); } catch (\Throwable) { continue; }
        $out[$host] ??= $current;
    }
    return $out;
}

/** Insert verified candidates under their category; existing entries are never removed. */
function addDiscovered(string $source, array $new): string {
    $keys=array_keys(categoryNames()); $known=readCategories($source); $groups=[];
    foreach ($new as $host=>$category) {
        $host=domain($host);
        if (isset($known[$host])) continue;
        if (!in_array($category, array_slice($keys,0,11), true)) throw new RuntimeException('Неизвестная категория кандидата');
        $groups[$category][]=$host;
    }
    if (!$groups) return $source;
    $lines=preg_split('/\r\n|\n|\r/', rtrim($source, "\r\n")); $out=[]; $current=null; $seen=[];
    $flush=function() use (&$current,&$groups,&$out,&$seen) {
        if ($current!==null && isset($groups[$current])) {
            sort($groups[$current],SORT_STRING);
            $out[]='# Добавлено автоматически после проверки DNS и RU IP';
            foreach(array_unique($groups[$current]) as $host) $out[]=$host;
            $seen[$current]=true;
        }
    };
    foreach($lines as $line) {
        if (preg_match('/^#\s*(\d+)\./u',$line,$m)) { $flush(); $current=$keys[(int)$m[1]-1] ?? null; }
        elseif (str_starts_with($line,'# Дополнения')) { $flush(); $current=null; }
        $out[]=$line;
    }
    $flush();
    if (array_diff(array_keys($groups),array_keys($seen))) throw new RuntimeException('Не найдены секции для новых доменов.');
    return implode("\n",$out)."\n";
}
function jsonFile(mixed $v): string { return json_encode($v, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n"; }
function catalogExports(array $entries, array $categories, array $report): array {
    $groups=array_fill_keys(array_keys(categoryNames()),[]); $all=[];
    foreach ($entries as $entry) {
        $host=$entry['hostname'];
        if (str_contains($host,'/')) continue;
        if (!isset($categories[$host]) || !isset($entry['ips']) || !is_array($entry['ips'])) throw new RuntimeException('Ошибка категории или адресов: '.$host);
        $groups[$categories[$host]][]=$entry; $all[]=$entry;
    }
    $files=[]; $metadata=[];
    foreach ($groups as $id=>$items) {
        $ips=[]; $domains=[];
        foreach ($items as $entry) { $domains[]=$entry['hostname']; foreach ($entry['ips'] as $ip) { if (!ipv4($ip)) throw new RuntimeException('Некорректный адрес'); $ips[$ip.'/32']=true; } }
        $cidrs=array_keys($ips); sort($cidrs); sort($domains);
        $clash="payload:\n"; foreach ($domains as $host) $clash.="  - 'DOMAIN-SUFFIX,$host'\n"; foreach ($cidrs as $net) $clash.="  - 'IP-CIDR,$net,no-resolve'\n";
        $base='category-'.$id;
        $files[$base.'-amnezia.json']=jsonFile($items);
        $files[$base.'-sing-box.json']=jsonFile(['version'=>3,'rules'=>[['domain_suffix'=>$domains,'ip_cidr'=>$cidrs]]]);
        $files[$base.'-clash.yaml']=$clash;
        $files[$base.'-cidr.txt']=$cidrs ? implode("\n",$cidrs)."\n" : '';
        $metadata[]=['id'=>$id,'name'=>categoryNames()[$id],'domains'=>count($items),'addresses'=>count($cidrs)];
    }
    $files['catalog.json']=jsonFile(['built_at'=>$report['built_at'],'categories'=>$metadata,'domain_categories'=>$categories,'entries'=>$all]);
    return $files;
}
function reportChanges(array $previous, array $current): array {
    $index=function($rows) { $out=[]; foreach($rows as $r) { if (!str_contains($r['hostname'],'/')) { $ips=$r['ips']; sort($ips); $out[$r['hostname']]=$ips; } } ksort($out); return $out; };
    $old=$index($previous); $new=$index($current); $changed=[];
    foreach (array_intersect_key($new,$old) as $host=>$ips) if ($ips!==$old[$host]) $changed[$host]=['before'=>$old[$host],'after'=>$ips];
    return ['previous_available'=>(bool)$previous,'added'=>array_values(array_diff(array_keys($new),array_keys($old))), 'removed'=>array_values(array_diff(array_keys($old),array_keys($new))), 'changed_ips'=>$changed];
}
