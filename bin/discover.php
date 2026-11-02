<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Routing.php';
require dirname(__DIR__).'/src/Sources.php';
require dirname(__DIR__).'/src/Catalog.php';
use RuRouting\Networks;
use function RuRouting\{fetch,fetchMany,lines,resolveMany,readCategories,upstreamCategories,addDiscovered,curatedDomains,candidateWindow,jsonFile};
try {
    $root=dirname(__DIR__);
    $url='https://raw.githubusercontent.com/kozlovartem20201/amnezia-vpn-russia/main/sources/domains.txt';
    $source=fetch($url); if (strlen($source)<3000) throw new RuntimeException('Сторонний список слишком мал.');
    $path=$root.'/sources/domains.txt'; $original=file_get_contents($path);
    if ($original===false) throw new RuntimeException('Каталог не прочитан.');
    $known=readCategories($original); $upstream=upstreamCategories($source);
    // Curated source categories only: no wildcard TLD, regex, or arbitrary includes.
    $feeds=['category-bank-ru'=>'banks','category-gov-ru'=>'government','category-medicine-ru'=>'health',
        'category-education-ru'=>'education','category-ecommerce-ru'=>'shops','category-retail-ru'=>'shops',
        'category-travel-ru'=>'travel','category-tech-media-ru'=>'technology'];
    $urls=[];foreach($feeds as $file=>$category) $urls[$file]='https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/'.$file;
    [$bodies,$failed]=fetchMany($urls,6,'text/plain');
    if ($failed) throw new RuntimeException('Один из источников недоступен: '.implode(', ',array_keys($failed)));
    foreach($feeds as $file=>$category) { if(strlen($bodies[$file])<50) throw new RuntimeException('Пустой источник '.$file); $upstream+=curatedDomains($bodies[$file],$category); }
    // Search common hostnames only under selected known services, not the whole .ru zone.
    foreach(['mos.ru','gosuslugi.ru','nalog.gov.ru','sberbank.ru','vtb.ru','tbank.ru','ozon.ru','wildberries.ru'] as $rootHost) {
        if (!isset($known[$rootHost])) continue;
        foreach(['api','id','login','lk','online','static','cdn'] as $prefix) $upstream[$prefix.'.'.$rootHost] ??= $known[$rootHost];
    }
    $candidates=array_diff_key($upstream,$known); $statusPath=$root.'/dist/discovery.json';
    $previous=is_file($statusPath)?json_decode(file_get_contents($statusPath),true,512,JSON_THROW_ON_ERROR):[];
    $cursor=is_string($previous['cursor']??null)?$previous['cursor']:'';
    $batch=candidateWindow($candidates,$cursor,100); $names=array_keys($batch); $matched=[]; $decisions=[];
    if ($names) {
        $ru=new Networks(lines(fetch('https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone')));
        if (count($ru->cidrs)<100) throw new RuntimeException('Список RU-сетей неполон.');
        [$answers,$errors]=resolveMany($names);
        foreach ($names as $host) {
            $ips=array_values(array_filter($answers[$host],fn($ip)=>$ru->contains($ip)));
            if (isset($errors[$host])) $decisions[$host]='dns_error';
            elseif (!$answers[$host]) $decisions[$host]='no_a_record';
            elseif (!$ips) $decisions[$host]='no_approved_ipv4';
            else { $matched[$host]=$batch[$host]; $decisions[$host]='accepted'; }
        }
    }
    $result=addDiscovered($original,$matched);
    if ($result!==$original && file_put_contents($path,$result,LOCK_EX)!==strlen($result)) throw new RuntimeException('Не удалось сохранить каталог.');
    $status=['checked_at'=>gmdate('c'),'cursor'=>$names ? end($names) : '', 'candidates_total'=>count($candidates),
        'checked'=>count($names),'added'=>array_keys($matched),'decisions'=>$decisions,
        'sources'=>['amnezia-vpn-russia','v2fly/domain-list-community','known-service-subdomains']];
    if (!is_dir(dirname($statusPath)) && !mkdir(dirname($statusPath),0755,true)) throw new RuntimeException('Нет каталога dist');
    if (file_put_contents($statusPath,jsonFile($status),LOCK_EX)===false) throw new RuntimeException('Очередь не сохранена.');
    echo count($matched).' новых доменов из '.count($names).', в очереди '.count($candidates)."\n";
} catch(Throwable $e) {fwrite(STDERR,'Ошибка: '.$e->getMessage()."\n");exit(1);}
