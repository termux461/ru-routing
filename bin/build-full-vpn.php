#!/usr/bin/env php
<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Routing.php';
require dirname(__DIR__).'/src/Sources.php';
require dirname(__DIR__).'/src/IPListSnapshot.php';
require dirname(__DIR__).'/src/VpnCatalog.php';
use function RuRouting\{fetch,fetchMany,sourceMap,snapshotGroup,telegramIpv4};
try {
    $root=dirname(__DIR__);
    $index=json_decode(file_get_contents($root.'/dist/portals.json'),true,512,JSON_THROW_ON_ERROR);
    if (!is_array($index['groups']??null) || count($index['groups'])<5) throw new RuntimeException('Индекс порталов неполон.');
    $urls=[];
    foreach($index['groups'] as $group) {
        $id=$group['id']??'';if(!is_string($id)||!preg_match('/^[a-z0-9_-]+$/D',$id)) throw new RuntimeException('Некорректная группа.');
        foreach(['ip4','cidr4','domains'] as $kind) $urls[$id.'|'.$kind]='https://iplist.opencck.org/?'.http_build_query(['format'=>'json','data'=>$kind,'group'=>$id]);
    }
    fwrite(STDERR,'Загружаю '.count($urls)." наборов из IPList…\n");
    [$responses,$errors]=fetchMany($urls,6,'application/json');
    if ($errors) throw new RuntimeException('Недоступны источники: '.implode(', ',array_keys($errors)).'. Предыдущая сборка сохранена.');
    $telegram=telegramIpv4(fetch('https://core.telegram.org/resources/cidr.txt'));
    $generated=[];$groups=[];$totalSites=0;$totalRoutes=0;$missing=[];$now=gmdate('c');$telegramSeen=false;
    foreach($index['groups'] as $group) {
        $id=$group['id'];$snapshot=snapshotGroup($group,sourceMap($responses[$id.'|ip4']),sourceMap($responses[$id.'|cidr4']),sourceMap($responses[$id.'|domains']),$now);
        if ($id==='messengers' && isset($snapshot['sites']['telegram.org'])) {
            $row=&$snapshot['sites']['telegram.org'];
            $row['routes']=array_values(array_unique(array_merge($row['routes'],$telegram)));sort($row['routes'],SORT_STRING);
            $row['additional_sources']=['https://core.telegram.org/resources/cidr.txt'];unset($row);$telegramSeen=true;
        }
        $sum=0;$available=0;$items=[];
        foreach($snapshot['sites'] as $name=>$site) { $sum+=count($site['routes']); if($site['routes'])$available++;if($site['missing_sources'])$missing[$id.'/'.$name]=$site['missing_sources']; $items[]=['id'=>$name,'routes'=>count($site['routes']),'missing'=>count($site['missing_sources'])]; }
        $totalSites+=count($snapshot['sites']);$totalRoutes+=$sum;
        $groups[]=['id'=>$id,'sites'=>count($snapshot['sites']),'available'=>$available,'rules'=>$sum,'items'=>$items];
        $name='full-'.$id.'.json';$oldPath=$root.'/dist/'.$name;
        if (is_file($oldPath)) {
            $old=json_decode(file_get_contents($oldPath),true);
            if(is_array($old)) { $candidate=$snapshot; $candidate['checked_at']=$old['checked_at']??null; if($candidate===$old) $snapshot['checked_at']=$old['checked_at']; }
        }
        $generated[$name]=json_encode($snapshot,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
    }
    if (!$telegramSeen) throw new RuntimeException('Telegram отсутствует в индексе; старые файлы сохранены.');
    if($totalSites<50 || $totalRoutes<100) throw new RuntimeException('Данных слишком мало: старые файлы сохранены.');
    $generated['full-manifest.json']=json_encode(['version'=>1,'built_at'=>$now,'portal_index_revision'=>$index['revision'],
        'source'=>'https://iplist.opencck.org/','source_fields'=>['ip4','cidr4','domains'], 'groups'=>$groups,
        'sites_total'=>$totalSites,'rules_total'=>$totalRoutes,'missing_sources'=>$missing],JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
    $stage=$root.'/.full-build-'.bin2hex(random_bytes(6));if(!mkdir($stage,0755))throw new RuntimeException('Нет временной папки.');
    try {
        foreach($generated as $name=>$content) if(file_put_contents($stage.'/'.$name,$content)!==strlen($content))throw new RuntimeException('Ошибка записи '.$name);
        foreach($generated as $name=>$_) if(!rename($stage.'/'.$name,$root.'/dist/'.$name))throw new RuntimeException('Ошибка публикации '.$name);
    } finally {foreach(glob($stage.'/*')?:[] as $p)unlink($p);rmdir($stage);}
    echo count($groups).' групп, '.$totalSites.' порталов, '.$totalRoutes." маршрутов до объединения\n";
} catch (Throwable $e) {fwrite(STDERR,'Ошибка: '.$e->getMessage()."\n");exit(1);}
