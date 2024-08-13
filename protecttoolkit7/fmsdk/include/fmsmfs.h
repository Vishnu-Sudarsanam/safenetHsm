/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fmsmfs.h
 */
#ifndef INCL_FMSMFS
#define INCL_FMSMFS

/**
 * @file
 * SMFS - Secure Memory File System as exported to FMs
 *
 * Arbitrary depth directory structure supported.
 * File names are any character other than '\0' or '/'.
 * Path seperator is '/' (the windows '\' is not allowed)
 * Files are fixed size and initialized with zeros when created.
 * Directories will expand in size as needed to fit more files.
 *
 * Current Important Constants are :-<br>
 *    Max file name length is 16<ul>
 *    Max path length is 100<ul>
 *    Max number of open files is 32<ul>
 *    Max number of file search handles is 16<ul>
 */

/* Error codes */
#ifndef SMFS_ERR_ERROR
#define SMFS_ERR_ERROR		1  /**< A general error has occured */
#define SMFS_ERR_NOT_INITED	2  /**< The SMFS has not been initialised */
#define SMFS_ERR_MEMORY		3  /**< The SMFS has run out of memory */
#define SMFS_ERR_NAME_TOO_LONG	4 /**< The name given for a file is too long */
#define SMFS_ERR_RESOURCES	5  /**< The SMFS has run out of resources */
#define SMFS_ERR_PARAMETER	6  /**< An invalid parameter was passed to SMFS */
#define SMFS_ERR_ACCESS		7  /**< User does not have request access to file*/
#define SMFS_ERR_NOT_FOUND	8  /**< Requested file was not found */
#define SMFS_ERR_BUSY		9  /**< Operation is being attempted on an open file*/
#define SMFS_ERR_EXIST		10 /**< A file being created already exists */
#define SMFS_ERR_FILE_TYPE	11 /**< Operation being performed on wrong file type*/

#endif


/** smfs file handle type */
#ifndef SMFS_HANDLE 
#define SMFS_HANDLE int
#endif

/**
 * File attribute structure
 */
typedef struct SmFsAttr {
    /** Current file size in bytes or dir size in entries */
	unsigned int 	Size;

    /** Flag specifying if file is a directory */
	unsigned int 	isDir;
} SmFsAttr;


/**
 * Allocates SRAM memory and a directory entry for a file. Once a file has
 * been created, its size cannot be changed.
 *
 * @param name
 *  Name (absolute path) of file to create
 *
 * @param len
 *  Size of file to create (in bytes)
 *
 * @return 0 for success or an error condition
 */
int SmFsCreateFile(const char * name,
					unsigned int len
					);

/**
 * Allocates SRAM memory and a directory entry for a file. Once a file has
 * been created, its size cannot be changed.
 * On flash file system (PSIe) the contents of the file are kept in the clear.
 * Use this function to store non sensitive data.
 * Read Write performance is better on these files.
 *
 * @param name
 *  Name (absolute path) of file to create
 *
 * @param len
 *  Size of file to create (in bytes)
 *
 * @return 0 for success or an error condition
 */
int SmFsCreateFileClr(const char * name,
					unsigned int len
					);

/**
 * Allocates SRAM memory and a directory entry for a directory.
 *
 * @param name
 *  Name (absolute path) of the directory to create 
 *
 * @param entries
 *  Maximum number of entries that may exist in the directory
 *
 * @return 0 for success or an error condition
 */
int SmFsCreateDir(const char * name,
        		  unsigned int entries
					 );

/**
 * Deletes a file from secure memory by removing the directory entry
 * and zeroing out its data area
 * 
 * @param name
 *  Name (absolute path) of file to delete
 *
 * @return 0 for success or an error condition
 */
int SmFsDeleteFile( const char * name
					);

/**
 * Finds the file and creates an entry for it in the file descriptor table.
 * This index is returned in 'fh' and is used by other file functions.
 *
 * @param fh
 *  Pointer to location to receive returned handle of opened file
 *
 * @param name
 *  Name (absolute path) of file to open
 *
 * @return 0 for success or an error condition
 */
int SmFsOpenFile( SMFS_HANDLE * fh,
  				  const char * name
					);

/**
 * Get attributes of an open file
 *
 * @param fh
 *  Handle of opened file
 *
 * @param a
 *  Pointer to location to receive the attributes of file
 *
 * @return 0 for success or an error condition
 */
int SmFsGetOpenFileAttr( SMFS_HANDLE fh,
						 SmFsAttr * a
					   );

/**
 * Get attributes of an unopened file
 *
 * @param name
 *  Name (absolute path) of file
 *
 * @param a
 *  Pointer to location to receive the attributes of file
 *
 * @return 0 for success or an error condition
 */
int SmFsGetFileAttr( const char * name,
					SmFsAttr * a
					);

/**
 * Read data from a file. It is an error to attempt to read past the end of 
 * the file. Reading a directory is possible but returns meaningless 
 * information. 
 *
 * @param fh
 *  Handle of opened file
 *
 * @param offset
 *  Zero based starting position 
 *
 * @param buf
 *  Pointer to location to receive read bytes
 *
 * @param bc
 * Number of bytes to read from file.
 * 
 * @return 0 for success or an error condition
 */
int SmFsReadFile(SMFS_HANDLE fh,
				  unsigned int offset,
				  char *buf,
				  unsigned int bc
				  );

/** 
 * Write data to a file. It is an error to attempt to write past the end of 
 * the file. You cannot write to a directory.
 *
 * @param fh
 *  Handle of opened file
 *
 * @param offset
 *  Zero based starting position
 *
 * @param buf
 *  Pointer to buffer to write to file
 *
 * @param bc
 *  Number of bytes in buf to write
 *
 * @return 0 for sucess or an error condition
 */
int SmFsWriteFile(SMFS_HANDLE fh,
				   unsigned int offset,
				   char *buf,
                   unsigned int bc
				   );


/**
 * Close the file by removing it from the file descriptor table
 *
 * @param fh
 *  Handle of file to close
 *
 * @return 0 for success or an error condition
 */
int SmFsCloseFile( SMFS_HANDLE fh
			     );

/**
 * Renames a file. 
 *
 * @param oldName
 * Name (absolute path) of file to rename
 *
 * @param newName
 *  New name (filename only - no path) of file
 *
 * @return 0 for success or an error condition
 */
int SmFsRenameFile( const char * oldName,
					const char * newName
					);

/**
 * Calculates and returns how much memory is free in the secure memory
 * file system
 *
 * @return Amount of free memory (in bytes) in the file system 
 */
unsigned int SmFsCalcFree( void );

/**
 * Creates a file iteration context
 * Wildcards supported are ? to match any character or * to match many.
 *
 * @param sh
 *  Pointer to location to hold search handle
 *
 * @param path
 *  Absolute path to search for file
 *
 * @param pattern
 *  Pattern of filename (with wildcards) to search for 
 *
 * @return 0 for success or an error condition
 */
int SmFsFindFileInit( int *sh,
					  const char * path,
					  const char * pattern
					  );

/**
 * Fetch name of next directory entry from file search context
 *
 * @param sh
 *  Search handle to continue
 *
 * @param name
 *  Pointer to location to hold found filename matching pattern
 *
 * @param size
 *  Length of name buffer
 *
 * @return 0 if found or an error condition
 */
int SmFsFindFile(int sh,
				  char * name,
				  unsigned int size
				  );

/**
 * Close a file search context
 *
 * @param sh
 *  Search handle to close
 *
 * @return 0 for success or an error condition
 */
int SmFsFindFileClose(int sh);


#endif /* INCL_FMSMFS */
