use protocol::{U2f, Challenge};
use messages::{RegisterResponse, RegisterRequest, U2fSignRequest, SignResponse};
use register::Registration;

fn verify_register(app_id: &str, req: &str, resp: &str) -> Registration {
    let reg:RegisterRequest = serde_json::from_str(req).unwrap();
    let resp:RegisterResponse = serde_json::from_str(resp).unwrap();

    let u2f = U2f::new(app_id.to_string());

    let challenge = Challenge {
        app_id: app_id.to_string(),
        challenge: reg.challenge,
        timestamp: format!("{:?}", chrono::Utc::now()),
    };

    u2f.register_response(challenge, resp).unwrap()
}

fn verify_auth(app_id: &str, reg: Registration, challenge: String, resp: &str) {

    let resp:SignResponse = serde_json::from_str(resp).unwrap();

    let u2f = U2f::new(app_id.to_string());

    let challenge = Challenge {
        app_id: app_id.to_string(),
        challenge,
        timestamp: format!("{:?}", chrono::Utc::now()),
    };

    let _ = u2f.sign_response(challenge, reg, resp, 0).unwrap();
}

#[test]
fn test_verify_register() {
    let app_id = "https://u2f.bin.coffee";

    let reg = r#"{ "version": "U2F_V2", "challenge": "6P5JxkcBo1n7MkYedNHMfasfv2U"}"#;
    let resp = r#"
    {"registrationData": "BQT0I6ocSkELiqqRc2MGai1raa3F49Q1d03UgWzu2eCADhPgSvXJsKzUIYERji0vxDlAElc4sZdm2ewnYXnDFOFrQAfHLIuUlJU3XsbiR9yO2kungl9EQB191MQm6sUx1-yE24i_KckdQzys5eel9hkLpFCptTi81FeaidzFd1DENqkwggEcMIHDoAMCAQICCwCqfKUQ4WrQsbjQMAoGCCqGSM49BAMCMBUxEzARBgNVBAMTClUyRiBJc3N1ZXIwGhcLMDAwMTAxMDAwMFoXCzAwMDEwMTAwMDBaMBUxEzARBgNVBAMTClUyRiBEZXZpY2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQLHNI5rXnrTB7a8UNEHI-1V1-WytEjyFyzE9XGbSVGIShjp3F8efxCDss3RgQVkRwKnEhlZt3npGa12j1zF3ttMAoGCCqGSM49BAMCA0gAMEUCIQDBo6aOLxanIUYnBX9iu3KMngPnobpi0EZSTkVtLC8_cwIgC1945RGqGBKfbyNtkhMifZK05n7fU-gW37Bdnci5D94wRQIgDl3K_Fefznq8etzJVSO75zaULRnyXWJhkGspAaXpqVsCIQC2M6zC5tpztFaBLpxV2JElJTyzN0pJ8uza-bkfAxBuXQ",
    "version": "U2F_V2",
    "clientData": "eyJjaGFsbGVuZ2UiOiI2UDVKeGtjQm8xbjdNa1llZE5ITWZhc2Z2MlUiLCJvcmlnaW4iOiJodHRwczovL3UyZi5iaW4uY29mZmVlIiwidHlwIjoibmF2aWdhdG9yLmlkLmZpbmlzaEVucm9sbG1lbnQifQ"
    }"#;

    let reg = verify_register(app_id, reg, resp);
    assert_eq!(reg.subject().as_ref().unwrap(), "U2F Device");
    assert_eq!(reg.issuer().as_ref().unwrap(), "U2F Issuer");

    let reg = r#"{"version": "U2F_V2","challenge": "LA9qqMYT7snzJkc_EVPiwdnOJpQ"}"#;
    let resp = r#"
    {
      "clientData": "eyJjaGFsbGVuZ2UiOiJMQTlxcU1ZVDdzbnpKa2NfRVZQaXdkbk9KcFEiLCJvcmlnaW4iOiJodHRwczovL3UyZi5iaW4uY29mZmVlIiwidHlwIjoibmF2aWdhdG9yLmlkLmZpbmlzaEVucm9sbG1lbnQifQ",
      "registrationData": "BQQmvjyTENSZrLCwioUt41_9fFlu32cZ68-aLRTmODtQGNWK_kjVyjR0XxjJzjHhqKk9Lqv5LsjsBRNrskUBXGAwQDQ4VdcmgylBfBLgzke5xIBSrbQefHzL87REVSdWu1zCmF86DT-sEqYawc-FE9AJzqpnQ-ESD-kNeoP0r4uDOCswggJKMIIBMqADAgECAgRXFvfAMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAsMSowKAYDVQQDDCFZdWJpY28gVTJGIEVFIFNlcmlhbCAyNTA1NjkyMjYxNzYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARk2RxU1tlXjdOwYHhMRjbVSKOYOq81J87rLcbjK2eeM_zp6GMUrbz4V1IbL0xJn5SvcFVlviIZWym2Tk2tDdBiozswOTAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNTATBgsrBgEEAYLlHAIBAQQEAwIFIDANBgkqhkiG9w0BAQsFAAOCAQEAeJsYypuk23Yg4viLjP3pUSZtKiJ31eP76baMmqDpGmpI6nVM7wveWYQDba5_i6P95ktRdgTDoRsubXVNSjcZ76h2kw-g4PMGP1pMoLygMU9_BaPqXU7dkdNKZrVdXI-obgDnv1_dgCN-s9uCPjTjEmezSarHnCSnEqWegEqqjWupJSaid6dx3jFqc788cR_FTSJmJ_rXleT0ThtwA08J_P44t94peJP7WayLHDPPxca-XY5Mwn9KH0b2-ET4eMByi9wd-6Zx2hCH9Yzjjllro_Kf0FlBXcUKoy-JFHzT2wgBN9TmW7zrC7_lQYgYjswUMRh5UZKrOnOHqaVyfxBIhjBFAiEAm-pV58Jt-RULRsB5UZDVdjV0Q1fgSXTJQGr_tZwur28CIHKQfJ_Dq_-ui4DT6n7BL6ulltuaQmny6_HXgJT0P_E_",
      "version": "U2F_V2"
    }
    "#;

    let reg = verify_register(app_id, reg, resp);
    assert_eq!(reg.subject().as_ref().unwrap(), "Yubico U2F EE Serial 250569226176");
    assert_eq!(reg.issuer().as_ref().unwrap(), "Yubico U2F Root CA Serial 457200631");

    let reg = r#"{"version": "U2F_V2","challenge": "x2ihLZaIcGhA-ByY2mgLc8aofEM"}"#;
    let resp = r#"
    {
      "clientData": "eyJjaGFsbGVuZ2UiOiJ4MmloTFphSWNHaEEtQnlZMm1nTGM4YW9mRU0iLCJvcmlnaW4iOiJodHRwczovL3UyZi5iaW4uY29mZmVlIiwidHlwIjoibmF2aWdhdG9yLmlkLmZpbmlzaEVucm9sbG1lbnQifQ",
      "registrationData": "BQS53KgoebC9HkJSbZM2r7C9oOnEysjR06iSnglpQIs6KeaCFwKQx6XbmrM2-p9BbdNOPvhF0GtUwNp7g7HznOIUUCzlyN8X4i7yD9ODA_0tmZjg1CmSI9If20U86SgMBqrcrK0radduqslZczEtivFMKXaaeqMT2rs7jfMb124XtnCwp4u5lCWVLYWMhmKyPlraMIIBJzCBzqADAgECAgF7MAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC0tyeXB0b24gS2V5MB4XDTIwMDEyNTIyNTMyOVoXDTMwMDEyNTEwNTMyOVowFjEUMBIGA1UEAwwLS3J5cHRvbiBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS53KgoebC9HkJSbZM2r7C9oOnEysjR06iSnglpQIs6KeaCFwKQx6XbmrM2-p9BbdNOPvhF0GtUwNp7g7HznOIUow0wCzAJBgNVHRMEAjAAMAoGCCqGSM49BAMCA0gAMEUCIQDeU4DwRJV_CAcormHMaYBYeTkFNQuUQsK77PF7jzy14QIgfXP5iop-DQqQjVkJUD11WeRvKCqZWRhyleQcRmsj584wRAIgf4vqsRgB6azPwVGGG6EDx4ioThOyLEfo8GPHWe7Pva8CIBE9P0-RlFgVOPQZFGlFWtzqzIy-3l4BkmIYgpSILlYt",
      "version": "U2F_V2"
    }
    "#;

    let reg = verify_register(app_id, reg, resp);
    assert_eq!(reg.subject().as_ref().unwrap(), "Krypton Key");
    assert_eq!(reg.issuer().as_ref().unwrap(), "Krypton Key");
}

#[test]
fn test_verify_auth() {
    let app_id = "https://u2f.bin.coffee";

    let reg = r#"{"version": "U2F_V2","challenge": "mjvdwudayivfuRrtTtxvej9BuGg"}"#;
    let resp = r#"
    {
      "clientData": "eyJjaGFsbGVuZ2UiOiJtanZkd3VkYXlpdmZ1UnJ0VHR4dmVqOUJ1R2ciLCJvcmlnaW4iOiJodHRwczovL3UyZi5iaW4uY29mZmVlIiwidHlwIjoibmF2aWdhdG9yLmlkLmZpbmlzaEVucm9sbG1lbnQifQ",
      "registrationData": "BQS--mwrFPzFsoiZYDqF_lr7MRayrQ8d5qvI3pG4P1Nbwzsc1p7Ew7AZ3fPGMiRTyp6xlOVMQYTUfe9C0gLYjQhaUCzlyN8X4i7yD9ODA_0tmZgfc4YP3fnZN_Wc83KUq-I7jNXEQfARXX1DF9rDrHiXpfz3WhAGFigln8hJhT_Ts28cHsE5lGtukPlVv8Y623krMIIBJzCBzqADAgECAgF7MAoGCCqGSM49BAMCMBYxFDASBgNVBAMMC0tyeXB0b24gS2V5MB4XDTIwMDEyNTIzMDY1N1oXDTMwMDEyNTExMDY1N1owFjEUMBIGA1UEAwwLS3J5cHRvbiBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS--mwrFPzFsoiZYDqF_lr7MRayrQ8d5qvI3pG4P1Nbwzsc1p7Ew7AZ3fPGMiRTyp6xlOVMQYTUfe9C0gLYjQhaow0wCzAJBgNVHRMEAjAAMAoGCCqGSM49BAMCA0gAMEUCIQDCC5erfPV34xhRxjcwCwRFrqnN8vpTsFKid3DB-pD2rgIgIjF40n3AvaCC2WGioKUbzXFXGQ0oFaALOEnnxTePmTswRQIgVY1DCRidvgaY6hr6vm1ImkhQ9E2TkUOeqf61QIPPVzACIQCxh8-_9pRpnklk6h4eCjxFFD6vKSwU9EoeNKoz1EBGuA",
      "version": "U2F_V2"
    }
    "#;

    let reg = verify_register(app_id, reg, resp);

    let resp = r#"
    {
        "clientData": "eyJjaGFsbGVuZ2UiOiJiUkxoMGZ4dTNEdk1yNXdzMnlsbW5RIiwib3JpZ2luIjoiaHR0cHM6Ly91MmYuYmluLmNvZmZlZSIsInR5cCI6Im5hdmlnYXRvci5pZC5nZXRBc3NlcnRpb24ifQ",
        "keyHandle": "LOXI3xfiLvIP04MD_S2ZmB9zhg_d-dk39ZzzcpSr4juM1cRB8BFdfUMX2sOseJel_PdaEAYWKCWfyEmFP9OzbxwewTmUa26Q-VW_xjrbeSs",
        "signatureData": "AQAAAAEwRAIgU4Kemc0A6fmxygmqe34NvBk2d4Fqy-kGN-RYV50jXK4CIFTb_fs1TA0grsffUInWmUdi94EPlqeK800KzdJY-iwH"
    }
    "#;

    let challenge = "bRLh0fxu3DvMr5ws2ylmnQ";

    verify_auth(app_id, reg, challenge.to_string(), resp);
}
