use std::{collections::HashMap, fmt::Display};

use axum::{
    body::Body,
    http::header::CONTENT_TYPE,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContentDescriptor {
    media_type: String,
    digest: String, // TODO: Use digest type
    size: u64,
    urls: Option<Vec<String>>,
    annotations: Option<HashMap<String, String>>,
    data: Option<String>,
    artifact_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImageManifest {
    schema_version: u32,

    media_type: String,
    annotations: Option<HashMap<String, String>>,
    artifact_type: Option<String>,

    config: ContentDescriptor,
    layers: Vec<ContentDescriptor>,
    subject: Option<ContentDescriptor>,
}

impl ImageManifest {
    pub(crate) fn media_type(&self) -> &str {
        self.media_type.as_ref()
    }
}

// TODO: Return error as:
// {
//     "errors:" [{
//             "code": <error identifier>,
//             "message": <message describing condition>,
//             "detail": <unstructured>
//         },
//         ...
//     ]
// }

#[derive(Debug, Serialize)]
pub(crate) struct OciError {
    code: ErrorCode,
    message: String,
    // not supported: detail
}

#[derive(Debug, Serialize)]
pub(crate) struct OciErrors {
    errors: Vec<OciError>,
}

impl OciErrors {
    pub(crate) fn single(error: OciError) -> Self {
        Self {
            errors: vec![error],
        }
    }
}

impl OciError {
    pub(crate) fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message: code.to_string(),
        } // TODO: Use actual message
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)]
pub(crate) enum ErrorCode {
    BlobUnknown,
    BlobUploadInvalid,
    BlobUploadUnknown,
    DigestInvalid,
    ManifestBlobUnknown,
    ManifestInvalid,
    ManifestUnknown,
    NameInvalid,
    NameUnknown,
    SizeInvalid,
    Unauthorized,
    Denied,
    Unsupported,
    #[serde(rename = "TOOMANYREQUESTS")]
    TooManyRequests,
}

// TOOD: Derive HTTP status from error code.

impl ErrorCode {
    fn message(&self) -> &'static str {
        match self {
            ErrorCode::BlobUnknown => "blob unknown to registry",
            ErrorCode::BlobUploadInvalid => "blob upload invalid",
            ErrorCode::BlobUploadUnknown => "blob upload unknown to registry",
            ErrorCode::DigestInvalid => "provided digest did not match uploaded content",
            ErrorCode::ManifestBlobUnknown => "blob unknown to registry",
            ErrorCode::ManifestInvalid => "manifest invalid",
            ErrorCode::ManifestUnknown => "manifest unknown",
            ErrorCode::NameInvalid => "invalid repository name",
            ErrorCode::NameUnknown => "repository name not known to registry",
            ErrorCode::SizeInvalid => "provided length did not match content length",
            ErrorCode::Unauthorized => "authentication required",
            ErrorCode::Denied => "requested access to the resource is denied",
            ErrorCode::Unsupported => "the operation is unsupported",
            ErrorCode::TooManyRequests => "too many requests",
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl IntoResponse for OciErrors {
    fn into_response(self) -> Response {
        Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_string(&self).expect("serialization should not fail"),
            ))
            .expect("did not expect body construction to fail")
    }
}

#[cfg(test)]
mod tests {
    use super::ImageManifest;

    #[test]
    fn simple_example_schema_parse() {
        let raw = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
               "mediaType": "application/vnd.docker.container.image.v1+json",
               "size": 2298,
               "digest": "sha256:e4c58958181a5925816faa528ce959e487632f4cfd192f8132f71b32df2744b4"
            },
            "layers": [
               {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "size": 30439111,
                  "digest": "sha256:43f89b94cd7df92a2f7e565b8fb1b7f502eff2cd225508cbd7ea2d36a9a3a601"
               }
            ]
        }"#;

        let _manifest: ImageManifest = serde_json::from_str(raw).expect("could not parse manifest");
    }
}
