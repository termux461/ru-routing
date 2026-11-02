<?php
declare(strict_types=1);
namespace RuRouting;
use RuntimeException;

function vpnServices(string $json): array {
    $data=json_decode($json,true,512,JSON_THROW_ON_ERROR);
    if (!is_array($data) || !$data || !isset($data['telegram'])) throw new RuntimeException('Нет списка сервисов Telegram.');
    $seen=[];
    foreach ($data as $id=>$group) {
        if (!is_string($id) || !preg_match('/^[a-z][a-z0-9-]{0,30}$/D',$id) || !is_array($group)
            || !is_string($group['name']??null) || trim($group['name'])==='' || !is_array($group['domains']??null) || !$group['domains']) throw new RuntimeException('Некорректная группа.');
        foreach ($group['domains'] as $host) {
            if (!is_string($host) || domain($host)!==$host || isset($seen[$host])) throw new RuntimeException('Некорректный или повторяющийся домен: '.(string)$host);
            $seen[$host]=$id;
        }
    }
    return $data;
}
function telegramIpv4(string $text): array {
    $result=[];
    foreach(lines($text) as $line) {
        if (str_contains($line,':')) { if (filter_var(explode('/',$line)[0],FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)===false) throw new RuntimeException('Некорректная запись IPv6 Telegram.'); continue; }
        [$net]=cidr($line);
        if ((int)explode('/',$net)[1]<16) throw new RuntimeException('Слишком широкая сеть Telegram.');
        $result[$net]=true;
    }
    if (count($result)<4 || count($result)>128) throw new RuntimeException('Некорректный список Telegram: обновление отменено.');
    $nets=array_keys($result);sort($nets,SORT_STRING);return $nets;
}
function vpnExports(array $services,array $telegram,callable $resolver,array $dnsErrors=[],?string $builtAt=null): array {
    $categories=[];$mapping=[];$entries=[];$skipped=[];$reasons=[];$total=0;
    foreach ($services as $id=>$group) {
        $count=0;
        foreach ($group['domains'] as $host) {
            $total++;$ips=array_values(array_unique(array_filter($resolver($host),__NAMESPACE__.'\\ipv4')));sort($ips,SORT_STRING);
            if (!$ips) { $skipped[]=$host;$reasons[$host]=isset($dnsErrors[$host])?'dns_error':'no_a_record';continue; }
            $mapping[$host]=$id;$entries[]=['hostname'=>$host,'ip'=>$ips[0],'ips'=>$ips];$count++;
        }
        if ($id==='telegram') foreach($telegram as $net) {
            [$net]=cidr($net);$mapping[$net]=$id;$entries[]=['hostname'=>$net,'ip'=>$net,'ips'=>[$net]];$count++;
        }
        $categories[]=['id'=>$id,'name'=>$group['name'],'rules'=>$count];
    }
    $hostCount=count($entries)-count($telegram);
    if ($hostCount<max(1,(int)ceil($total*0.30))) throw new RuntimeException('Слишком мало работающих доменов. Старые файлы сохранены.');
    $json=fn($d)=>json_encode($d,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
    $timestamp=$builtAt??gmdate('c');
    $domains=[];$nets=[];
    foreach($entries as $row) {
        if (!str_contains($row['hostname'],'/')) $domains[]=$row['hostname'];
        foreach($row['ips'] as $ip) $nets[str_contains($ip,'/')?$ip:$ip.'/32']=true;
    }
    sort($domains);$nets=array_keys($nets);sort($nets);
    $clash="payload:\n";
    foreach($domains as $host) $clash.="  - 'DOMAIN-SUFFIX,$host'\n";
    foreach($nets as $net) $clash.="  - 'IP-CIDR,$net,no-resolve'\n";
    return [
        'vpn-catalog.json'=>$json(['built_at'=>$timestamp,'mode'=>'selected-through-vpn','categories'=>$categories,'domain_categories'=>$mapping,'entries'=>$entries]),
        'vpn-list.json'=>$json($entries),
        'vpn-sing-box.json'=>$json(['version'=>3,'rules'=>[['domain_suffix'=>$domains,'ip_cidr'=>$nets]]]),
        'vpn-clash.yaml'=>$clash,
        'vpn-ipv4.txt'=>implode("\n",$nets)."\n",
        'vpn-report.json'=>$json(['built_at'=>$timestamp,'mode'=>'selected-through-vpn','domains_total'=>$total,'domains_accepted'=>$hostCount,
            'telegram_ipv4_networks'=>count($telegram),'skipped_domains'=>$skipped,'skip_reasons'=>$reasons,'dns_errors'=>$dnsErrors,
            'telegram_source'=>'https://core.telegram.org/resources/cidr.txt']),
    ];
}
