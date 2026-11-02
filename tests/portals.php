<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/PortalIndex.php';
use function RuRouting\portalIndex;
function ck(bool $ok,string $name): void { if (!$ok) throw new RuntimeException($name); }
function failTest(callable $fn): bool {try {$fn();return false;} catch(Throwable) {return true;}}
$tree=['sha'=>str_repeat('a',40),'truncated'=>false,'tree'=>[
 ['type'=>'blob','path'=>'config/social/example.com.json'],['type'=>'blob','path'=>'config/social/other.json'],
 ['type'=>'blob','path'=>'config/social/example.com.json'],['type'=>'blob','path'=>'config/other/../escape.json'],
 ['type'=>'blob','path'=>'config/social/../../oops.json'],['type'=>'blob','path'=>'config/social/evil?.json'],
 ['type'=>'tree','path'=>'config/social/skip.json'],['type'=>'blob','path'=>'config/social/notjson.txt'],
]];
$parsed=portalIndex(json_encode($tree),'2026-01-01T00:00:00Z');
ck($parsed['count']===2 && $parsed['groups'][0]['sites']===['example.com','other'],'dedup and validated identities');
$tree['truncated']=true;ck(failTest(fn()=>portalIndex(json_encode($tree))),'truncated tree rejected');
$tree['truncated']=false;$tree['sha']='bad';ck(failTest(fn()=>portalIndex(json_encode($tree))),'invalid revision rejected');
ck(failTest(fn()=>portalIndex('{}')),'missing tree rejected');
echo "OK: portal indexing and malformed sources\n";
