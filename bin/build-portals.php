<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Routing.php';
require dirname(__DIR__).'/src/PortalIndex.php';
use function RuRouting\portalIndex;
try {
    $root=dirname(__DIR__);
    $url='https://api.github.com/repos/rekryt/iplist/git/trees/master?recursive=1';
    if (!extension_loaded('curl')) throw new RuntimeException('Требуется PHP curl.');
    $token=getenv('GITHUB_TOKEN')?:''; $body=false; $status=0;
    foreach ($token!==''?[$token,'']:[''] as $credential) {
        $ch=curl_init($url);$headers=['Accept: application/vnd.github+json'];
        if ($credential!=='') $headers[]='Authorization: Bearer '.$credential;
        curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>10,CURLOPT_TIMEOUT=>30,
            CURLOPT_FOLLOWLOCATION=>false,CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS,
            CURLOPT_USERAGENT=>'ru-routing-portal-index/1.0',CURLOPT_HTTPHEADER=>$headers]);
        $body=curl_exec($ch);$status=curl_getinfo($ch,CURLINFO_RESPONSE_CODE);curl_close($ch);
        if (is_string($body) && $status===200 && strlen($body)<=8000000) break;
    }
    if (!is_string($body) || $status!==200 || strlen($body)>8000000) throw new RuntimeException('Источник индекса недоступен (HTTP '.$status.').');
    $data=portalIndex($body);
    if ($data['count']<50 || count($data['groups'])<5) throw new RuntimeException('Список порталов слишком мал; старый файл сохранён.');
    $oldPath=$root.'/dist/portals.json';
    if (is_file($oldPath)) { $old=json_decode(file_get_contents($oldPath),true); if (is_array($old) && ($old['revision']??null)===$data['revision'] && is_string($old['generated_at']??null)) $data['generated_at']=$old['generated_at']; }
    $json=json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
    if (!is_dir($root.'/dist') && !mkdir($root.'/dist',0755,true)) throw new RuntimeException('Не удалось создать dist.');
    $tmp=$root.'/dist/.portals-'.bin2hex(random_bytes(5));
    try {
        if (file_put_contents($tmp,$json)!==strlen($json) || !rename($tmp,$root.'/dist/portals.json')) throw new RuntimeException('Не удалось сохранить индекс.');
    } finally { if (is_file($tmp)) unlink($tmp); }
    echo $data['count']." порталов, ".count($data['groups'])." групп\n";
} catch (Throwable $e) {fwrite(STDERR,'Ошибка: '.$e->getMessage()."\n");exit(1);}
