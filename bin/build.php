#!/usr/bin/env php
<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/Routing.php';
require dirname(__DIR__) . '/src/Sources.php';

use RuRouting\Networks;
use function RuRouting\{lines, fetch, build, domain, resolveMany, loadAsnNetworks, checkRegression};

try {
    if (PHP_INT_SIZE < 8) {
        throw new RuntimeException('Требуется 64-битный PHP 8.2+.');
    }
    foreach (array_slice($argv, 1) as $arg) {
        if (!in_array($arg, ['--all-ru', '--help'], true)) {
            throw new RuntimeException("Неизвестный аргумент: $arg");
        }
    }
    if (in_array('--help', $argv, true)) {
        echo "php bin/build.php [--all-ru]\nПо умолчанию: только IP выбранных сервисов. --all-ru: добавить все IPv4-подсети RU.\n";
        exit(0);
    }
    $root = dirname(__DIR__);
    $lock = fopen($root . '/.build.lock', 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
        throw new RuntimeException('Другая сборка уже запущена.');
    }
    $read = function (string $path): string {
        $data = file_get_contents($path);
        if ($data === false) {
            throw new RuntimeException("Не удалось прочитать $path");
        }
        return $data;
    };
    fwrite(STDERR, "Загрузка RU-подсетей…\n");
    $ru = new Networks(lines(fetch('https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone')));
    if (count($ru->cidrs) < 100) {
        throw new RuntimeException('Слишком маленький список RU-подсетей. Сборка отменена.');
    }
    $domains = array_values(array_unique(array_map('RuRouting\\domain', lines($read($root . '/sources/domains.txt')))));
    fwrite(STDERR, "Загрузка подсетей сервисов из RIPEstat…\n");
    [$services, $protection, $asnReport] = loadAsnNetworks(lines($read($root . '/sources/asn.txt')),
        lines($read($root . '/sources/protection-asn.txt')), $ru);
    fwrite(STDERR, 'Проверка DNS для ' . count($domains) . " доменов и www…\n");
    [$answers, $dnsErrors] = resolveMany($domains);
    $files = build($domains, $ru, new Networks(lines($read($root . '/sources/cidr.txt'))),
        fn($host) => $answers[$host], in_array('--all-ru', $argv, true), $services, $protection, $dnsErrors);
    $report = json_decode($files['report.json'], true, 512, JSON_THROW_ON_ERROR);
    $report['asn'] = $asnReport;
    $report['www_checked'] = true;
    $report['sources'] = [
        'country' => 'https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone',
        'announcements' => 'https://stat.ripe.net/data/announced-prefixes/data.json',
        'domain_source_sha256' => hash_file('sha256', $root . '/sources/domains.txt'),
    ];
    if (is_file($root . '/dist/report.json')) {
        $previous = json_decode($read($root . '/dist/report.json'), true, 512, JSON_THROW_ON_ERROR);
        checkRegression($previous, $report);
    }
    $files['report.json'] = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    $stage = $root . '/.build-' . bin2hex(random_bytes(6));
    if (!mkdir($stage, 0755)) {
        throw new RuntimeException('Не удалось создать временную папку.');
    }
    try {
        foreach ($files as $name => $content) {
            if (file_put_contents($stage . '/' . $name, $content) !== strlen($content)) {
                throw new RuntimeException("Ошибка записи $name");
            }
        }
        if (!is_dir($root . '/dist') && !mkdir($root . '/dist', 0755)) {
            throw new RuntimeException('Не удалось создать dist.');
        }
        foreach ($files as $name => $_) {
            if (!rename($stage . '/' . $name, $root . '/dist/' . $name)) {
                throw new RuntimeException("Ошибка публикации $name");
            }
        }
    } finally {
        foreach (glob($stage . '/*') ?: [] as $path) {
            unlink($path);
        }
        rmdir($stage);
    }
    echo $files['report.json'];
} catch (Throwable $error) {
    fwrite(STDERR, 'Ошибка: ' . $error->getMessage() . "\n");
    exit(1);
}
