# SimpleSAMLphp negotiate-ext module

![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-negotiateext/actions/workflows/php.yml/badge.svg)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-negotiateext/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-negotiateext/?branch=master)
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-negotiateext/branch/master/graph/badge.svg)](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-negotiateext)
[![Type Coverage](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-negotiateext/coverage.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-negotiateext)
[![Psalm Level](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-negotiateext/level.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-negotiateext)

## Install

Install with composer

```bash
vendor/bin/composer require simplesamlphp/simplesamlphp-module-negotiateext
```

## Configuration

Next thing you need to do is to enable the module:

in `config.php`, search for the `module.enable` key and set `negotiateext` to true:

```php
'module.enable' => [ 'negotiateext' => true, … ],
```
