-- execute these to install InnoDB if it is built as a dynamic plugin
INSTALL PLUGIN innodb SONAME 'ha_innodb.dll';
INSTALL PLUGIN innodb_trx SONAME 'ha_innodb.dll';
INSTALL PLUGIN innodb_locks SONAME 'ha_innodb.dll';
INSTALL PLUGIN innodb_lock_waits SONAME 'ha_innodb.dll';
INSTALL PLUGIN innodb_cmp SONAME 'ha_innodb.dll';
INSTALL PLUGIN innodb_cmp_reset SONAME 'ha_innodb.dll';
INSTALL PLUGIN innodb_cmpmem SONAME 'ha_innodb.dll';
INSTALL PLUGIN innodb_cmpmem_reset SONAME 'ha_innodb.dll';
