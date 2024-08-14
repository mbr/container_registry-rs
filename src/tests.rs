use std::sync::Arc;

use axum::{
    body::Body,
    http::{
        header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_RANGE, LOCATION},
        Request, StatusCode,
    },
};
use base64::Engine;
use http_body_util::BodyExt;
use sec::Secret;
use tokio::io::AsyncWriteExt;
use tower::{util::ServiceExt, Service};

use crate::{
    auth::Anonymous,
    storage::{ImageLocation, ManifestReference, Reference},
    test_support::TestingContainerRegistry,
    ImageDigest,
};

use super::{storage::Digest, ContainerRegistry};

/// Constructs a basic auth header with the [`TEST_PASSWORD`].
fn basic_auth() -> String {
    let encoded =
        base64::prelude::BASE64_STANDARD.encode(format!("user:{}", TEST_PASSWORD).as_bytes());
    format!("Basic {}", encoded)
}

/// Constructs a basic auth header that is guaranteed to NOT be the [`TEST_PASSWORD`].
fn invalid_basic_auth() -> String {
    let not_the_password = "user:not-the-password".to_owned() + TEST_PASSWORD;
    let encoded = base64::prelude::BASE64_STANDARD.encode(not_the_password.as_bytes());
    format!("Basic {}", encoded)
}

const TEST_PASSWORD: &str = "random-test-password";

fn registry_with_test_password() -> TestingContainerRegistry {
    ContainerRegistry::builder()
        .auth_provider(Arc::new(Secret::new(TEST_PASSWORD.to_owned())))
        .build_for_testing()
}

fn registry_with_test_password_and_full_anon_access() -> TestingContainerRegistry {
    ContainerRegistry::builder()
        .auth_provider(Arc::new(Anonymous::new(
            crate::auth::Permissions::ReadWrite,
            Secret::new(TEST_PASSWORD.to_owned()),
        )))
        .build_for_testing()
}

#[tokio::test]
async fn refuses_access_without_valid_credentials() {
    let ctx = registry_with_test_password();
    let mut service = ctx.make_service();
    let app = service.ready().await.expect("could not launch service");

    let targets = [("GET", "/v2/")];
    // TODO: Verify all remaining endpoints return `UNAUTHORIZED` without credentials.

    for (method, endpoint) in targets.into_iter() {
        // API should refuse requests without credentials.
        let response = app
            .call(
                Request::builder()
                    .method(method)
                    .uri(endpoint)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Wrong credentials should also not grant access.
        let response = app
            .call(
                Request::builder()
                    .method(method)
                    .uri(endpoint)
                    .header(AUTHORIZATION, invalid_basic_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Finally a valid set should grant access.
        let response = app
            .call(
                Request::builder()
                    .uri("/v2/")
                    .header(AUTHORIZATION, basic_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED)
    }
}

#[tokio::test]
async fn allows_anon_access_if_configured() {
    let ctx = registry_with_test_password_and_full_anon_access();
    let mut service = ctx.make_service();
    let app = service.ready().await.expect("could not launch service");

    let targets = [("GET", "/v2/")];

    for (method, endpoint) in targets.into_iter() {
        // Wrong credentials should still not grant access.
        let response = app
            .call(
                Request::builder()
                    .method(method)
                    .uri(endpoint)
                    .header(AUTHORIZATION, invalid_basic_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Valid credentials should grant access
        let response = app
            .call(
                Request::builder()
                    .uri("/v2/")
                    .header(AUTHORIZATION, basic_auth())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);

        // No cretentials should also grant access
        let response = app
            .call(
                Request::builder()
                    .method(method)
                    .uri(endpoint)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

// Fixtures.
const RAW_IMAGE: &[u8] =
    include_bytes!("../fixtures/596a7d877b33569d199046aaf293ecf45026445be36de1818d50b4f1850762ad");
const RAW_MANIFEST: &[u8] =
    include_bytes!("../fixtures/9ce67038e4f1297a0b1ce23be1b768ce3649fe9bd496ba8efe9ec1676d153430");

const IMAGE_DIGEST: ImageDigest = ImageDigest::new(Digest::new([
    0x59, 0x6a, 0x7d, 0x87, 0x7b, 0x33, 0x56, 0x9d, 0x19, 0x90, 0x46, 0xaa, 0xf2, 0x93, 0xec, 0xf4,
    0x50, 0x26, 0x44, 0x5b, 0xe3, 0x6d, 0xe1, 0x81, 0x8d, 0x50, 0xb4, 0xf1, 0x85, 0x07, 0x62, 0xad,
]));

const MANIFEST_DIGEST: ImageDigest = ImageDigest::new(Digest::new([
    0x9c, 0xe6, 0x70, 0x38, 0xe4, 0xf1, 0x29, 0x7a, 0x0b, 0x1c, 0xe2, 0x3b, 0xe1, 0xb7, 0x68, 0xce,
    0x36, 0x49, 0xfe, 0x9b, 0xd4, 0x96, 0xba, 0x8e, 0xfe, 0x9e, 0xc1, 0x67, 0x6d, 0x15, 0x34, 0x30,
]));

#[tokio::test]
async fn chunked_upload() {
    // See https://github.com/opencontainers/distribution-spec/blob/v1.0.1/spec.md#pushing-a-blob-in-chunks
    let ctx = registry_with_test_password();
    let mut service = ctx.make_service();
    let app = service.ready().await.expect("could not launch service");

    // Step 1: POST for new blob upload.
    let response = app
        .call(
            Request::builder()
                .method("POST")
                .header(AUTHORIZATION, basic_auth())
                .uri("/v2/tests/sample/blobs/uploads/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let put_location = response
        .headers()
        .get(LOCATION)
        .expect("expected location header for blob upload")
        .to_str()
        .unwrap()
        .to_owned();

    // Step 2: PATCH blobs.
    let mut sent = 0;
    for chunk in RAW_IMAGE.chunks(32) {
        assert!(!chunk.is_empty());
        let range = format!("{sent}-{}", chunk.len() - 1);
        sent += chunk.len();

        let response = app
            .call(
                Request::builder()
                    .method("PATCH")
                    .header(AUTHORIZATION, basic_auth())
                    .header(CONTENT_LENGTH, chunk.len())
                    .header(CONTENT_RANGE, range)
                    .uri(&put_location)
                    .body(Body::from(chunk))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // Step 3: PUT without (!) final body -- we do not support putting the final piece in `PUT`.
    let response = app
        .call(
            Request::builder()
                .method("PUT")
                .header(AUTHORIZATION, basic_auth())
                .uri(put_location + "?digest=" + IMAGE_DIGEST.to_string().as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Check the blob is available after.
    let blob_location = format!("/v2/tests/sample/blobs/{}", IMAGE_DIGEST);
    assert!(&ctx
        .registry
        .storage
        .get_blob_reader(IMAGE_DIGEST.digest)
        .await
        .expect("could not access stored blob")
        .is_some());

    // Step 4: Client verifies existence of blob through `HEAD` request.
    let response = app
        .call(
            Request::builder()
                .method("HEAD")
                .header(AUTHORIZATION, basic_auth())
                .uri(blob_location)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        IMAGE_DIGEST.to_string()
    );

    // Step 5: Upload the manifest
    let manifest_by_tag_location = "/v2/tests/sample/manifests/latest";

    let response = app
        .call(
            Request::builder()
                .method("PUT")
                .header(AUTHORIZATION, basic_auth())
                .uri(manifest_by_tag_location)
                .body(Body::from(RAW_MANIFEST))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        MANIFEST_DIGEST.to_string()
    );

    // Should contain image under given tag.
    assert_eq!(
        ctx.registry
            .storage
            .get_manifest(&ManifestReference::new(
                ImageLocation::new("tests".to_owned(), "sample".to_owned()),
                Reference::new_tag("latest"),
            ))
            .await
            .expect("failed to get reference by tag")
            .expect("missing reference by tag"),
        RAW_MANIFEST
    );

    assert_eq!(
        ctx.registry
            .storage
            .get_manifest(&ManifestReference::new(
                ImageLocation::new("tests".to_owned(), "sample".to_owned()),
                Reference::new_digest(MANIFEST_DIGEST.digest),
            ))
            .await
            .expect("failed to get reference by digest")
            .expect("missing reference by digest"),
        RAW_MANIFEST
    );
}

/// Similar to `chunked_upload`, but uses no credentials to log in.
#[tokio::test]
async fn anonymous_upload() {
    let ctx = ContainerRegistry::builder().build_for_testing();

    let mut service = ctx.make_service();
    let app = service.ready().await.expect("could not launch service");

    // Step 1: POST for new blob upload.
    let response = app
        .call(
            Request::builder()
                .method("POST")
                .uri("/v2/tests/sample/blobs/uploads/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let put_location = response
        .headers()
        .get(LOCATION)
        .expect("expected location header for blob upload")
        .to_str()
        .unwrap()
        .to_owned();

    // Step 2: PATCH blobs.
    let mut sent = 0;
    for chunk in RAW_IMAGE.chunks(32) {
        assert!(!chunk.is_empty());
        let range = format!("{sent}-{}", chunk.len() - 1);
        sent += chunk.len();

        let response = app
            .call(
                Request::builder()
                    .method("PATCH")
                    .header(CONTENT_LENGTH, chunk.len())
                    .header(CONTENT_RANGE, range)
                    .uri(&put_location)
                    .body(Body::from(chunk))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // Step 3: PUT without (!) final body -- we do not support putting the final piece in `PUT`.
    let response = app
        .call(
            Request::builder()
                .method("PUT")
                .uri(put_location + "?digest=" + IMAGE_DIGEST.to_string().as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Check the blob is available after.
    let blob_location = format!("/v2/tests/sample/blobs/{}", IMAGE_DIGEST);
    assert!(&ctx
        .registry
        .storage
        .get_blob_reader(IMAGE_DIGEST.digest)
        .await
        .expect("could not access stored blob")
        .is_some());

    // Step 4: Client verifies existence of blob through `HEAD` request.
    let response = app
        .call(
            Request::builder()
                .method("HEAD")
                .uri(blob_location)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        IMAGE_DIGEST.to_string()
    );

    // Step 5: Upload the manifest
    let manifest_by_tag_location = "/v2/tests/sample/manifests/latest";

    let response = app
        .call(
            Request::builder()
                .method("PUT")
                .uri(manifest_by_tag_location)
                .body(Body::from(RAW_MANIFEST))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap(),
        MANIFEST_DIGEST.to_string()
    );
}

#[tokio::test]
async fn image_download() {
    let ctx = registry_with_test_password();
    let mut service = ctx.make_service();
    let app = service.ready().await.expect("could not launch service");

    let manifest_ref_by_tag = ManifestReference::new(
        ImageLocation::new("tests".to_owned(), "sample".to_owned()),
        Reference::new_tag("latest"),
    );

    let manifest_by_tag_location = "/v2/tests/sample/manifests/latest";
    let manifest_by_digest_location = format!("/v2/tests/sample/manifests/{}", MANIFEST_DIGEST);

    // Insert blob data.
    let upload = ctx
        .registry
        .storage
        .begin_new_upload()
        .await
        .expect("could not start upload");
    let mut writer = ctx
        .registry
        .storage
        .get_upload_writer(0, upload)
        .await
        .expect("could not create upload writer");
    writer
        .write_all(RAW_IMAGE)
        .await
        .expect("failed to write image blob");
    ctx.registry
        .storage
        .finalize_upload(upload, IMAGE_DIGEST.digest)
        .await
        .expect("failed to finalize upload");

    // Insert manifest data.
    ctx.registry
        .storage
        .put_manifest(&manifest_ref_by_tag, RAW_MANIFEST)
        .await
        .expect("failed to store manifest");

    // Retrieve manifest via HTTP, both by tag and by digest.
    let response = app
        .call(
            Request::builder()
                .method("GET")
                .header(AUTHORIZATION, basic_auth())
                .uri(manifest_by_tag_location)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = collect_body(response.into_body()).await;

    assert_eq!(response_body, RAW_MANIFEST);

    let response = app
        .call(
            Request::builder()
                .method("GET")
                .header(AUTHORIZATION, basic_auth())
                .uri(manifest_by_digest_location)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = collect_body(response.into_body()).await;

    assert_eq!(response_body, RAW_MANIFEST);

    // Download blob.
    let response = app
        .call(
            Request::builder()
                .method("GET")
                .header(AUTHORIZATION, basic_auth())
                .uri(format!("/v2/testing/sample/blobs/{}", IMAGE_DIGEST))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let response_body = collect_body(response.into_body()).await;
    assert_eq!(response_body, RAW_IMAGE);
}

#[tokio::test]
async fn missing_manifest_returns_404() {
    let ctx = registry_with_test_password();
    let mut service = ctx.make_service();
    let app = service.ready().await.expect("could not launch service");

    let response = app
        .call(
            Request::builder()
                .method("GET")
                .header(AUTHORIZATION, basic_auth())
                .uri("/v2/doesnot/exist/manifests/latest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[test]
fn run_in_background_in_sync_test() {
    let ctx = ContainerRegistry::builder().build_for_testing();
    let running = ctx.run_in_background();

    // Wait a bit.
    std::thread::sleep(std::time::Duration::from_millis(100));

    // TODO: Test HTTP interface (don't want to pull in deps for this at the moment).

    drop(running);
}

async fn collect_body(mut body: Body) -> Vec<u8> {
    let mut rv = Vec::new();
    while let Some(frame_result) = body.frame().await {
        let data = frame_result
            .expect("failed to retrieve body frame")
            .into_data()
            .expect("not a data frame");

        rv.extend(data.to_vec());
    }

    rv
}
