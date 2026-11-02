<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Routing.php';
require dirname(__DIR__).'/src/Sources.php';
require dirname(__DIR__).'/src/Catalog.php';
use RuRouting\Networks;
use function RuRouting\{fetch,lines,domain,resolveMany,readCategories};
try {
    $root=dirname(__DIR__);
    $url='https://raw.githubusercontent.com/kozlovartem20201/amnezia-vpn-russia/main/sources/domains.txt';
    $source=fetch($url); if (strlen($source)<3000) throw new RuntimeException('Сторонний список слишком мал.');
    $known=readCategories(file_get_contents($root.'/sources/domains.txt'));
    $candidates=[];
    foreach(lines($source) as $host) {
        try { $host=domain($host); } catch (Throwable) { continue; }
        if (!isset($known[$host])) $candidates[$host]=true;
    }
    $names=array_keys($candidates); sort($names); $names=array_slice($names,0,100);
    $matched=[]; $errors=[];
    if ($names) {
        $ru=new Networks(lines(fetch('https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone')));
        if (count($ru->cidrs)<100) throw new RuntimeException('Список RU-сетей неполон.');
        [$answers,$errors]=resolveMany($names);
        foreach ($names as $host) {
            $ips=array_values(array_filter($answers[$host],fn($ip)=>$ru->contains($ip)));
            if ($ips) $matched[$host]=array_values(array_unique($ips));
        }
    }
    $out="# Кандидаты на добавление\n\nИсточник: [amnezia-vpn-russia]($url). Это предложения для ручной проверки, список маршрутизации они не меняют.\n\n";
    $out.="Проверены наличие в текущем каталоге и IPv4 из базы RU IPdeny. Это не доказывает принадлежность сервиса, доступность из РФ или отсутствие общих IP. Перед добавлением проверьте сервис и выберите категорию в sources/domains.txt.\n\n";
    foreach($matched as $host=>$ips) $out.='- `'.$host.'` — `'.implode('`, `',$ips)."`\n";
    if (!$matched) $out.="Подходящих новых доменов нет.\n";
    if ($errors) $out.="\nНекоторые DNS-запросы завершились ошибкой; проверьте запуск workflow.\n";
    if ($matched) file_put_contents($root.'/CANDIDATES.md',$out,LOCK_EX);
    elseif (is_file($root.'/CANDIDATES.md')) unlink($root.'/CANDIDATES.md');
    echo count($matched)." кандидатов\n";
} catch(Throwable $e) {fwrite(STDERR,'Ошибка: '.$e->getMessage()."\n");exit(1);}
