use tower_http::{
    classify::StatusInRangeAsFailures, decompression::DecompressionLayer, set_header::SetRequestHeaderLayer, trace::TraceLayer
};
use tower::{ServiceBuilder, Service, ServiceExt};
use hyper_util::{rt::TokioExecutor, client::legacy::Client, client::proxy::matcher};
use http_body_util::{BodyExt, Full};
use bytes::Bytes;
use http::{HeaderValue, Request, Uri, header::USER_AGENT};

pub async fn make_request() {
    let proxy_matcher = matcher::Matcher::from_env();

    let client = Client::builder(TokioExecutor::new()).build_http();
        let mut client = ServiceBuilder::new()
            // Add tracing and consider server errors and client
            // errors as failures.
            .layer(TraceLayer::new(
                StatusInRangeAsFailures::new(400..=599).into_make_classifier()
            ))
            // Set a `User-Agent` header on all requests.
            .layer(SetRequestHeaderLayer::overriding(
                USER_AGENT,
                HeaderValue::from_static("tower-http demo")
            ))
            // Decompress response bodies
            .layer(DecompressionLayer::new())
            // Wrap a `Client` in our middleware stack.
            // This is possible because `Client` implements
            // `tower::Service`.
            .service(client);

        let mut uri: Uri = "http://example.com".try_into().unwrap();
        if let Some(intercept) = proxy_matcher.intercept(&uri) {
            uri = intercept.uri().clone();
        }
    
        // Make a request
        let request = Request::builder()
            .uri(uri)
            .body(Full::<Bytes>::default())
            .unwrap();
    
        let response = client
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();

        let body = response.into_body();
        let bytes = body.collect().await.unwrap().to_bytes().to_vec();
        let body = String::from_utf8(bytes).unwrap();
        println!("{}", body);

    }