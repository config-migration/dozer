"""Database tables for strace objects."""


# Imports
from sqlalchemy.exc import OperationalError
from sqlalchemy.schema import (
    Column, ForeignKey, Index, MetaData, Table, UniqueConstraint
)
from sqlalchemy.types import BINARY, BLOB, INTEGER, JSON, TEXT, VARCHAR

from lib import logger, mysql_engine


# Constants
CHAR_MAX_LEN = 255
BINARY_MAX_LEN = 2 ** 32 - 1
SHA1_LEN = 20


# Types
LONGBLOB = BLOB(length=BINARY_MAX_LEN)
LONGTEXT = TEXT(length=BINARY_MAX_LEN)
LONGVARCHAR = VARCHAR(length=CHAR_MAX_LEN)
SHA1 = BINARY(length=SHA1_LEN)


# Table metadata
metadata = MetaData(bind=mysql_engine)


# All known strace executables and arguments
executables = Table(
    'executables',
    metadata,
    Column('id', INTEGER, primary_key=True),
    Column('system', LONGVARCHAR, nullable=False),
    Column('executable', LONGVARCHAR, nullable=False),
    Column('arguments_hash', SHA1, nullable=False),
    Column('arguments', JSON, nullable=False),
    Index('system', 'executable', 'arguments_hash'),
)


# Raw straces
straces = Table(
    'straces',
    metadata,
    Column('id', INTEGER, primary_key=True),
    Column(
        'executable',
        None,
        ForeignKey(executables.c.id, onupdate='CASCADE'),
        nullable=False
    ),
    Column('collector', LONGVARCHAR, nullable=False),
    Column('collector_assigned_id', LONGVARCHAR, nullable=False),
    Column('strace', LONGTEXT, nullable=False),
    Column('metadata', JSON, nullable=False),
    Column('json', JSON, nullable=False),
    Column('pickle', LONGBLOB, nullable=False),
    UniqueConstraint('collector', 'collector_assigned_id'),
)


# Strace argument holes
argument_holes = Table(
    'syscall_argument_holes',
    metadata,
    Column('id', INTEGER, primary_key=True),
    Column('syscall', LONGVARCHAR, nullable=False),
    Column('index', INTEGER, nullable=False),
    UniqueConstraint('syscall', 'index'),
)


# Known executables that don't have a corresponding strace
untraced_executables = Table(
    'untraced_executables',
    metadata,
    Column('id', INTEGER, primary_key=True),
    Column('system', LONGVARCHAR, nullable=False),
    Column('executable', LONGVARCHAR, nullable=False),
    Column('arguments_hash', SHA1, nullable=False),
    Column('arguments', JSON, nullable=False),
    Index('system', 'executable', 'arguments_hash'),
)


# Create all tables
try:
    metadata.create_all()
except OperationalError as e:
    logger.exception('Unable to create database tables.')
    exit(1)

