<?php
declare(strict_types=1);
namespace RuRouting;
use RuntimeException;

/** Index only portal identities from a GitHub tree, never external URLs or raw rules. */
function portalIndex(string $json, ?string $builtAt=null): array {
    $tree=json_decode($json,true,512,JSON_THROW_ON_ERROR);
    if (($tree['truncated']??true)!==false || !is_array($tree['tree']??null) || !preg_match('/^[a-f0-9]{40}$/D',$tree['sha']??'')) throw new RuntimeException('Некорректный или неполный индекс источника.');
    $groups=[];
    foreach ($tree['tree'] as $entry) {
        if (($entry['type']??'')!=='blob' || !is_string($entry['path']??null)) continue;
        if (!preg_match('~^config/([a-z0-9_-]+)/([a-z0-9_@.-]+)\\.json$~iD',$entry['path'],$m)) continue;
        [$ignore,$group,$site]=$m;
        if ($site==='.' || $site==='..' || str_contains($site,'..')) continue;
        $groups[$group][$site]=true;
    }
    ksort($groups,SORT_STRING);$out=[];$count=0;
    foreach ($groups as $id=>$sites) { $names=array_keys($sites);sort($names,SORT_NATURAL|SORT_FLAG_CASE);$count+=count($names);$out[]=['id'=>$id,'sites'=>$names]; }
    return ['generated_at'=>$builtAt??gmdate('c'),'revision'=>$tree['sha'],'source'=>'https://github.com/rekryt/iplist','count'=>$count,'groups'=>$out];
}
