#!/usr/bin/env php
<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Routing.php';
require dirname(__DIR__).'/src/Sources.php';
require dirname(__DIR__).'/src/VpnCatalog.php';
use function RuRouting\{fetch,vpnServices,telegramIpv4,resolveMany,vpnExports};
try {
    $root=dirname(__DIR__);if (PHP_INT_SIZE<8) throw new RuntimeException('Нужен 64-битный PHP.');
    $services=vpnServices(file_get_contents($root.'/sources/vpn-services.json'));
    $networks=telegramIpv4(fetch('https://core.telegram.org/resources/cidr.txt'));
    $hosts=[];foreach($services as $group) $hosts=array_merge($hosts,$group['domains']);
    fwrite(STDERR,"Проверка DNS для ".count($hosts)." доменов…\n");
    [$answers,$errors]=resolveMany($hosts);
    $files=vpnExports($services,$networks,fn($host)=>$answers[$host],$errors);
    $stage=$root.'/.vpn-build-'.bin2hex(random_bytes(6));if(!mkdir($stage,0755)) throw new RuntimeException('Не удалось создать временный каталог.');
    try {
        foreach($files as $name=>$content) if(file_put_contents($stage.'/'.$name,$content)!==strlen($content)) throw new RuntimeException('Ошибка записи '.$name);
        if(!is_dir($root.'/dist')&&!mkdir($root.'/dist',0755)) throw new RuntimeException('Не удалось создать dist.');
        foreach($files as $name=>$_) if(!rename($stage.'/'.$name,$root.'/dist/'.$name)) throw new RuntimeException('Ошибка публикации '.$name);
    } finally { foreach(glob($stage.'/*')?:[] as $p) unlink($p); rmdir($stage); }
    echo $files['vpn-report.json'];
} catch(Throwable $e) {fwrite(STDERR,'Ошибка: '.$e->getMessage()."\n");exit(1);}
