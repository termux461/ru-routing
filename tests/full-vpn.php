<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Routing.php';require dirname(__DIR__).'/src/IPListSnapshot.php';
use function RuRouting\{snapshotSite,sourceMap,snapshotGroup};
function verifyFull(bool $ok,string $message): void {if(!$ok)throw new RuntimeException($message);}
function failsFull(callable $f): bool {try{$f();return false;}catch(Throwable){return true;}}
$row=snapshotSite(['8.8.8.8','8.8.4.4','127.0.0.1','1.1.1.1'],['8.8.8.0/24','10.0.0.0/8','8.8.8.0/24'],['foo.example','foo.example','bad..example','_bad.example']);
verifyFull(in_array('8.8.8.0/24',$row['routes'],true) && !in_array('8.8.8.8/32',$row['routes'],true),'network covers original address');
verifyFull(in_array('8.8.4.4/32',$row['routes'],true) && in_array('1.1.1.1/32',$row['routes'],true),'IPs outside subnet remain');
verifyFull(!in_array('10.0.0.0/8',$row['routes'],true) && $row['rejected']===4,'special-use and invalid names counted');
verifyFull($row['domains']===['foo.example'],'valid domains deduplicated');
verifyFull(failsFull(fn()=>sourceMap('{"example":42}')),'invalid API shapes fail');
$g=snapshotGroup(['id'=>'video','sites'=>['a.example','b.example']],['a.example'=>['1.1.1.1']],['a.example'=>[]],['a.example'=>['a.example']],'2026-01-01');
verifyFull($g['sites']['b.example']['missing_sources']===['ip4','cidr4','domains'],'missing data reported');
verifyFull(failsFull(fn()=>snapshotGroup(['id'=>'../bad','sites'=>[]],[],[],[])),'group path traversal rejected');
echo "OK: complete IPv4 coverage, filters and source validation\n";
