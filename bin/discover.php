<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Routing.php';
require dirname(__DIR__).'/src/Sources.php';
require dirname(__DIR__).'/src/Catalog.php';
use RuRouting\Networks;
use function RuRouting\{fetch,lines,resolveMany,readCategories,upstreamCategories,addDiscovered};
try {
    $root=dirname(__DIR__);
    $url='https://raw.githubusercontent.com/kozlovartem20201/amnezia-vpn-russia/main/sources/domains.txt';
    $source=fetch($url); if (strlen($source)<3000) throw new RuntimeException('Сторонний список слишком мал.');
    $path=$root.'/sources/domains.txt'; $original=file_get_contents($path);
    if ($original===false) throw new RuntimeException('Каталог не прочитан.');
    $known=readCategories($original); $upstream=upstreamCategories($source);
    $candidates=array_diff_key($upstream,$known); ksort($candidates);
    $names=array_slice(array_keys($candidates),0,100); $matched=[];
    if ($names) {
        $ru=new Networks(lines(fetch('https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone')));
        if (count($ru->cidrs)<100) throw new RuntimeException('Список RU-сетей неполон.');
        [$answers,$errors]=resolveMany($names);
        foreach ($names as $host) {
            if (isset($errors[$host])) continue;
            foreach ($answers[$host] as $ip) if ($ru->contains($ip)) { $matched[$host]=$candidates[$host]; break; }
        }
    }
    $result=addDiscovered($original,$matched);
    if ($result!==$original && file_put_contents($path,$result,LOCK_EX)!==strlen($result)) throw new RuntimeException('Не удалось сохранить каталог.');
    echo count($matched)." новых доменов\n";
} catch(Throwable $e) {fwrite(STDERR,'Ошибка: '.$e->getMessage()."\n");exit(1);}
