/*
   *  Configuration file for SEOS filesystem.
   *
   *  Copyright (C) 2019, Hensoldt Cyber GmbH
*/

#pragma once

// Max. partition per disk
#define PARTITION_COUNT                     10

// Max. file handle per partition
#define FILE_HANDLE_COUNT                   10

// FAT config
#define FILE_DIR_ENTRY_COUNT                16
#define FS_HEADER_SECTOR_COUNT              1
#define CLUSTER_SIZE_FAT                    0x200   // size of cluster = 512 Byte
#define OFFSET_SECTORS_COUNT_FAT            3

// setup dataports, if filesystem build as component
#define GET_PROPERTY_FS_DATAPORT_BUFFER     (void *)fs_dataport_buf
#define SEOS_DATABUFFER_SIZE                4096
