export {};

declare global {
    /**
     * Represents the dictionary for hash algorithm and value.
     */
    interface CrossOriginStorageGetFileHandleHash {
        value: string;
        algorithm: string;
    }

    /**
     * Represents the options for requesting a file handle.
     */
    interface CrossOriginStorageGetFileHandleOptions {
        create?: boolean | undefined;
        origins?: string[] | string | undefined;
    }

    /**
     * The CrossOriginStorageManager interface.
     * [SecureContext]
     */
    interface CrossOriginStorageManager {
        getFileHandle(
            hash: CrossOriginStorageGetFileHandleHash,
            options?: CrossOriginStorageGetFileHandleOptions,
        ): Promise<FileSystemFileHandle>;
    }

    interface Navigator {
        readonly crossOriginStorage: CrossOriginStorageManager;
    }

    interface WorkerNavigator {
        readonly crossOriginStorage: CrossOriginStorageManager;
    }
}