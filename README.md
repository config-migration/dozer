# Dozer

Dozer helps you build configuration scripts.

## How it Works

A single configuration task can be expressed in many configuration languages. 
Dozer maps task behaviors by inspecting system calls and can use mapping 
information to help you push configuration task definitions between languages.
If you give Dozer a source configuration task and a target language, it will
return a target configuration task that makes similar system changes.

See the [sycall](http://man7.org/linux/man-pages/man2/syscalls.2.html) 
reference for additional information on available Linux system calls.

## Dependencies

| Name   | Version    | URL                                | Description                   |
| ------ | ---------- | ---------------------------------- | ----------------------------- |
| Python |        3.8 | https://www.python.org/            | Language.                     |
| Pipenv |  2021.5.29 | https://pipenv.pypa.io/en/latest/  | Python dependency management. |
| MySQL  |          8 | https://www.mysql.com/             | Database.                     | 
| Docker |    20.10.8 | https://www.docker.com/            | Container management.         |


## Setting up for development

Configure a Python environment with.

```
$ pipenv sync --keep-outdated
```

Start services with Docker compose.

```
$ docker-compose up --detach
```

Grab a database backup from releases and restore it (see [Database](#database) 
for additional details).

```
$ gunzip -c path/to/backup.sql | pv -btra | docker exec -i dozer.mysql mysql -C --max-allowed-packet=1G dozer
```

Show help to see where to get started.

```
$ python dozer.py --help
```


## Database

To back up the database, run

```
$ docker exec -it dozer.mysql mysqldump -Cceq --single-transaction --max-allowed-packet=1G dozer | pv -btra | gzip -9 -c > computed/backups/yyyy-MM-ddTHH:mm.sql.gz
```

To restore the database, run

```
$ gunzip -c computed/backups/yyyy-MM-ddTHH:mm.sql | pv -btra | docker exec -i dozer.mysql mysql -C --max-allowed-packet=1G dozer
```

The use of `pv` ([pipe viewer](http://www.ivarch.com/programs/pv.shtml)) and/or 
`gzip` is optional but recommended.

### Importing Records

It may be useful to import traces from an external source and merge them into
the local database. For example, this may be desired to integrate traces 
collected on a separate build server. 

The simplest method for importing records is by doing a backup and restore.
Note that this _*WILL NOT*_ preserve unique executables in the database.
After restoring the records to be imported to the local database `backup`, 
run:

```sql
SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE;
BEGIN;

    SELECT MAX(id) INTO @max_executable_id FROM dozer.executables;
    UPDATE backup.executables SET id = id + @max_executable_id ORDER BY id DESC;

    SELECT MAX(id) INTO @max_strace_id FROM dozer.straces;
    UPDATE backup.straces SET id = id + @max_strace_id ORDER BY id DESC;
    
    INSERT INTO dozer.executables SELECT * FROM backukp.executables;
    INSERT INTO dozer.straces SELECT * FROM backup.straces;

COMMIT;
``` 
