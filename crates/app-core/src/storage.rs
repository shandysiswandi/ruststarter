//! A modular, provider-agnostic service for file storage.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Failed to create directory: {0}")]
    CreateDirFailed(#[source] std::io::Error),

    #[error("Failed to write file: {0}")]
    WriteFileFailed(#[source] std::io::Error),

    #[error("Unknown storage error")]
    Unknown,
}

#[cfg_attr(feature = "testing", mockall::automock)]
#[async_trait::async_trait]
pub trait StorageService: Send + Sync {
    async fn upload_file(&self, file_name: &str, data: Vec<u8>, content_type: &str) -> Result<String, StorageError>;
}

#[cfg(feature = "storage-local")]
pub mod local {
    use std::path::PathBuf;

    use async_trait::async_trait;
    use tokio::fs;

    use super::*;

    /// An implementation of `StorageService` that saves files to the local
    /// disk.
    #[derive(Clone)]
    pub struct LocalStorageService {
        base_path: PathBuf,
        base_url: String,
    }

    impl LocalStorageService {
        pub fn new(base_path: String, base_url: String) -> Self {
            Self { base_path: PathBuf::from(base_path), base_url }
        }
    }

    #[async_trait]
    impl StorageService for LocalStorageService {
        async fn upload_file(&self, file_name: &str, data: Vec<u8>, _: &str) -> Result<String, StorageError> {
            let file_path = self.base_path.join(file_name);

            // Ensure the base directory exists.
            if let Some(parent_dir) = file_path.parent() {
                fs::create_dir_all(parent_dir).await.map_err(StorageError::CreateDirFailed)?;
            }

            // Write the file
            fs::write(&file_path, data).await.map_err(StorageError::WriteFileFailed)?;

            // Construct the public URL.
            Ok(format!("{}/{}", self.base_url, file_name))
        }
    }
}

#[cfg(feature = "storage-gcp")]
pub mod gcp {
    use super::*;

    /// A placeholder implementation for Google Cloud Storage.
    /// To implement this, you would add the `gcloud-sdk` or a similar crate.
    #[derive(Clone)]
    pub struct GcpStorageService {
        // client: gcloud_sdk::storage::Client,
        bucket_name: String,
    }

    impl GcpStorageService {
        pub fn new(bucket_name: String) -> Self {
            // Initialize the GCS client here.
            todo!("Initialize GCS client");
        }
    }

    #[async_trait]
    impl StorageService for GcsStorageService {
        async fn upload_file(&self, _file_name: &str, _data: Vec<u8>, _content_type: &str) -> Result<String, AppError> {
            // Implement the GCS upload logic here.
            // 1. Use the client to upload the data.
            // 2. Construct and return the public URL.
            todo!("Implement GCS file upload");
        }
    }
}

#[cfg(feature = "storage-aws")]
pub mod aws {
    // This could use the `aws-sdk-s3` crate by configuring it with a custom
    // endpoint.
    use aws_sdk_s3::Client;

    use super::*;

    #[derive(Clone)]
    pub struct AwsStorageService {
        client: Client,
        bucket_name: String,
        public_url: String,
    }

    impl AwsStorageService {
        pub async fn new(bucket_name: String, region: String, endpoint: String, public_url: String) -> Self {
            let config = aws_config::from_env()
                .region(aws_config::Region::new(region))
                .endpoint_url(endpoint)
                .load()
                .await;
            let client = Client::new(&config);
            Self { client, bucket_name, public_url }
        }
    }

    #[async_trait]
    impl StorageService for MinioStorageService {
        async fn upload_file(&self, file_name: &str, data: Vec<u8>, content_type: &str) -> Result<String, AppError> {
            self.client
                .put_object()
                .bucket(&self.bucket_name)
                .key(file_name)
                .body(data.into())
                .content_type(content_type)
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("Failed to upload to MinIO: {}", e);
                    AppError::Internal
                })?;

            // Construct the public URL using the configured base URL.
            let url = format!("{}/{}/{}", self.public_url, self.bucket_name, file_name);
            Ok(url)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;
    use tokio::fs;

    use super::StorageService;
    use super::local::LocalStorageService;

    #[tokio::test]
    async fn test_local_upload_file() {
        // Arrange
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path().to_string_lossy().to_string();
        let base_url = "http://localhost/files".to_string();

        let service = LocalStorageService::new(base_path.clone(), base_url.clone());

        let file_name = "test_dir/hello.txt";
        let file_data = b"Hello, storage!".to_vec();
        let content_type = "text/plain";

        // Act
        let result = service.upload_file(file_name, file_data.clone(), content_type).await.unwrap();

        // Assert: URL correctness
        assert_eq!(result, format!("{}/{}", base_url, file_name));

        // Assert: file existence and content
        let written_path = Path::new(&base_path).join(file_name);
        assert!(written_path.exists());

        let stored_data = fs::read(written_path).await.unwrap();
        assert_eq!(stored_data, file_data);
    }
}
