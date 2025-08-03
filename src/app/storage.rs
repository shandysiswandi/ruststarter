//! A modular, provider-agnostic service for file storage.

use crate::app::error::AppError;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait StorageService: Send + Sync {
    async fn upload_file(
        &self,
        file_name: &str,
        data: Vec<u8>,
        content_type: &str,
    ) -> Result<String, AppError>;
}

#[cfg(feature = "storage-local")]
pub mod local {
    use super::*;
    use async_trait::async_trait;
    use std::path::PathBuf;
    use tokio::fs;

    /// An implementation of `StorageService` that saves files to the local disk.
    #[derive(Clone)]
    pub struct LocalStorageService {
        base_path: PathBuf,
        base_url: String,
    }

    impl LocalStorageService {
        pub fn new(base_path: String, base_url: String) -> Self {
            Self {
                base_path: PathBuf::from(base_path),
                base_url,
            }
        }
    }

    #[async_trait]
    impl StorageService for LocalStorageService {
        async fn upload_file(
            &self,
            file_name: &str,
            data: Vec<u8>,
            _content_type: &str,
        ) -> Result<String, AppError> {
            let file_path = self.base_path.join(file_name);

            // Ensure the base directory exists.
            if let Some(parent_dir) = file_path.parent() {
                fs::create_dir_all(parent_dir).await.map_err(|e| {
                    tracing::error!("Failed to create upload directory: {}", e);
                    AppError::Internal
                })?;
            }

            fs::write(&file_path, data).await.map_err(|e| {
                tracing::error!("Failed to write file to disk: {}", e);
                AppError::Internal
            })?;

            // Construct the public URL.
            let url = format!("{}/{}", self.base_url, file_name);
            Ok(url)
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
        async fn upload_file(
            &self,
            _file_name: &str,
            _data: Vec<u8>,
            _content_type: &str,
        ) -> Result<String, AppError> {
            // Implement the GCS upload logic here.
            // 1. Use the client to upload the data.
            // 2. Construct and return the public URL.
            todo!("Implement GCS file upload");
        }
    }
}

#[cfg(feature = "storage-aws")]
pub mod aws {
    use super::*;
    // This could use the `aws-sdk-s3` crate by configuring it with a custom endpoint.
    use aws_sdk_s3::Client;

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
            Self {
                client,
                bucket_name,
                public_url,
            }
        }
    }

    #[async_trait]
    impl StorageService for MinioStorageService {
        async fn upload_file(
            &self,
            file_name: &str,
            data: Vec<u8>,
            content_type: &str,
        ) -> Result<String, AppError> {
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
