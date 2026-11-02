<?php
declare(strict_types=1);
namespace RuRouting;
use RuntimeException;

/** Keep every public input address covered by a returned route; discard special-use networks. */
function snapshotSite(array $ips,array $cidrs,array $domains): array {
    $networks=[];$invalid=0;
    foreach ($cidrs as $value) {
        if (!is_string($value)) { $invalid++; continue; }
        try { [$net]=cidr($value);$networks[$net]=true; } catch (\Throwable) { $invalid++; }
    }
    $networkSet=new Networks(array_keys($networks));
    $singles=[];
    foreach ($ips as $value) {
        if (!is_string($value) || !ipv4($value)) { $invalid++; continue; }
        if (!$networkSet->contains($value)) $singles[$value.'/32']=true;
    }
    $routes=array_values(array_unique(array_merge(array_keys($networks),array_keys($singles))));sort($routes,SORT_STRING);
    $names=[];
    foreach ($domains as $value) {
        if (!is_string($value)) { $invalid++;continue; }
        try { $host=domain($value);$names[$host]=true; } catch (\Throwable) { $invalid++; }
    }
    $names=array_keys($names);sort($names,SORT_STRING);
    return ['routes'=>$routes,'domains'=>$names,'source_ip_count'=>count($ips),'source_network_count'=>count($cidrs),'rejected'=> $invalid];
}
function sourceMap(string $json): array {
    $value=json_decode($json,true,512,JSON_THROW_ON_ERROR);
    if (!is_array($value)) throw new RuntimeException('Источник вернул не список сервисов.');
    foreach ($value as $site=>$items) {
        if (!is_string($site) || !is_array($items) || !array_is_list($items)) throw new RuntimeException('Некорректные данные портала.');
    }
    return $value;
}
function snapshotGroup(array $indexGroup,array $ip4,array $cidr4,array $domains,?string $time=null): array {
    $id=$indexGroup['id']??null;
    if (!is_string($id) || !preg_match('/^[a-z0-9_-]+$/D',$id) || !is_array($indexGroup['sites']??null)) throw new RuntimeException('Некорректная группа.');
    $sites=[];
    foreach ($indexGroup['sites'] as $site) {
        if (!is_string($site) || !preg_match('/^[a-z0-9_@.-]+$/iD',$site) || str_contains($site,'..')) throw new RuntimeException('Некорректный портал.');
        $missing=[];foreach(['ip4'=>$ip4,'cidr4'=>$cidr4,'domains'=>$domains] as $key=>$map) if(!array_key_exists($site,$map)) $missing[]=$key;
        $record=snapshotSite($ip4[$site]??[], $cidr4[$site]??[], $domains[$site]??[]);
        $record['missing_sources']=$missing;
        $sites[$site]=$record;
    }
    return ['version'=>1,'group'=>$id,'source'=>'https://iplist.opencck.org/','checked_at'=>$time??gmdate('c'),'sites'=>$sites];
}
