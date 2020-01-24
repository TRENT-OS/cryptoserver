/*
   *  Configuration file for SEOS partition manager.
   *
   *  Copyright (C) 2019, Hensoldt Cyber GmbH
*/

#pragma once

// internal defines
#define PARTITION_CONFIGURATION_AT(x)           partition_conf.partition[x]
#define SEOS_ARRAY_SIZE(x)                      (sizeof(x)/sizeof(x[0]))

#define GET_PROPERTY_PARTITION_NAME_AT(x)       PARTITION_CONFIGURATION_AT(x).partition_name
#define GET_PROPERTY_PARTITION_SIZE_AT(x)       PARTITION_CONFIGURATION_AT(x).partition_size

// setup disk/partition
#define GET_PROPERTY_PARTITION_COUNT            SEOS_ARRAY_SIZE(partition_conf.partition)
#define GET_PROPERTY_DISK_SIZE                  disk_information.disk_size

#ifdef FAT_FS
#define GET_PROPERTY_BLOCK_SIZE                 disk_information.block_size_default
#endif

#ifndef FAT_FS
#define GET_PROPERTY_BLOCK_SIZE                 1
#endif

#define GET_PROPERTY_PARTITION_NAME(x)          GET_PROPERTY_PARTITION_NAME_AT(x)
#define GET_PROPERTY_PARTITION_SIZE(x)          GET_PROPERTY_PARTITION_SIZE_AT(x)

// setup dataports, if build partition manager as component
#define GET_PROPERTY_PM_DATAPORT_BUFFER         (void *)pm_dataport_buf
#define SEOS_DATABUFFER_SIZE                    4096
