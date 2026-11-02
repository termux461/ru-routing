<?php
declare(strict_types=1);
$root=dirname(__DIR__).'/dist/';
$read=fn($file)=>json_decode(file_get_contents($root.$file),true,512,JSON_THROW_ON_ERROR);
$catalog=$read('vpn-catalog.json');$list=$read('vpn-list.json');$sing=$read('vpn-sing-box.json');$report=$read('vpn-report.json');
if ($catalog['mode']!=='selected-through-vpn' || $catalog['entries']!==$list || $sing['version']!==3) throw new RuntimeException('Format mismatch');
$telegram=array_filter($list,fn($x)=>str_contains($x['hostname'],'/') && ($catalog['domain_categories'][$x['hostname']]??null)==='telegram');
if(count($telegram)<4 || count($telegram)!==$report['telegram_ipv4_networks']) throw new RuntimeException('Telegram networks missing');
foreach($telegram as $entry) {
    if(!in_array($entry['hostname'],$sing['rules'][0]['ip_cidr'],true)) throw new RuntimeException('Telegram missing from sing-box');
    if(!str_contains(file_get_contents($root.'vpn-clash.yaml'), 'IP-CIDR,'.$entry['hostname'].',no-resolve')) throw new RuntimeException('Telegram missing from Clash');
}
echo 'OK: '.count($list).' VPN rules, '.count($telegram)." Telegram IPv4 networks\n";
