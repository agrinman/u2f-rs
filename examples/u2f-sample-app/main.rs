#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_derive;

use std::io;

use u2f::protocol::*;
use u2f::messages::*;
use u2f::register::*;

use std::sync::Mutex;

use warp::{Filter, Reply};
use warp::reply::Json;
use std::borrow::Borrow;

use sodiumoxide::crypto::secretbox;

static APP_ID : &'static str = "https://localhost:30443";

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    sodiumoxide::init().unwrap();

    // GET /hello/warp => 200 OK with body "Hello, warp!"
    let index = warp::get().and(warp::path(""));

    let register = warp::post()
        .and(warp::path("api/register_request"))
        .map(register_request);

    let reg_done = warp::post()
        .and(warp::path("api/register_response"))
        .and(warp::body::json())
        .and(warp::cookie::cookie("challenge"))
        .map(register_response);

    let routes = index.or(register).or(reg_done);

    warp::serve(routes)
        .run(([127, 0, 0, 1], 30443))
        .await;
}

lazy_static! {
    // In a real application this could be a database lookup.
    static ref REGISTRATIONS: Mutex<Vec<Registration>> = {
        let registrations: Mutex<Vec<Registration>> = Mutex::new(vec![]);
        registrations
    };

    static ref COOKIE_KEY: secretbox::Key = { secretbox::gen_key() };
}

fn seal(data: &[u8]) -> String {
    let nonce = secretbox::gen_nonce();
    let ctxt = secretbox::seal(data, &nonce, &COOKIE_KEY);
    let out = vec![nonce.0.borrow(), ctxt.as_slice()].concat();
    base64::encode_config(&out, base64::URL_SAFE_NO_PAD)
}

fn unseal(data: &str) -> std::result::Result<Vec<u8>, failure::Error> {
    let out = base64::decode_config(data.as_bytes(), base64::URL_SAFE_NO_PAD)?;

    if out.len() < secretbox::NONCEBYTES {
        return Err(failure::err_msg("invalid cookie"));
    }

    let nonce = secretbox::Nonce::from_slice(&out[..secretbox::NONCEBYTES]).unwrap();
    let ctxt = &out[secretbox::NONCEBYTES..];
    let message = secretbox::open(ctxt, &nonce, &COOKIE_KEY).map_err(|_| failure::err_msg("decrypt failed"))?;
    Ok(message)
}

fn index() -> &'static str {
    include_str!("static/index.html")
}

fn register_request() -> impl warp::Reply {
    let u2f = U2f::new(APP_ID.to_string());

    let challenge = u2f.generate_challenge().unwrap();
    let challenge_str = serde_json::to_string(&challenge).unwrap();

    // Send registration request to the browser.
    let u2f_request = u2f.request(challenge.clone(), REGISTRATIONS.lock().unwrap().clone()).unwrap();

    let challenge = seal(challenge_str.as_bytes());
    let body =  warp::reply::json(&u2f_request);

    warp::reply::with_header(body, "cookie", format!("challenge={}", challenge))
}

fn register_response(response: RegisterResponse, cookie: String) -> impl Reply {
    let u2f = U2f::new(APP_ID.to_string());

    #[derive(Serialize)]
    struct Response {
        status: String
    }

    let challenge = match unseal(cookie.as_str()) {
        Ok(chal) => chal,
        Err(e) => {
            eprintln!("invalid cookie: {:?}", e);
            let resp = warp::reply::json(&Response { status: "no challenge".to_string()});
            return warp::reply::with_status(resp, warp::http::StatusCode::NOT_FOUND);
        }
    };

    let challenge: Challenge = serde_json::from_slice(challenge.as_slice()).unwrap();
    let registration = u2f.register_response(challenge, response);

    match registration {
        Ok(reg) =>  {
            REGISTRATIONS.lock().unwrap().push(reg);
            let resp = warp::reply::json(&Response { status: "success".to_string()});
            warp::reply::with_status(resp, warp::http::StatusCode::OK)
        },
        Err(e) => {
            let resp = warp::reply::json(&Response { status: "registration not found".to_string()});
            warp::reply::with_status(resp, warp::http::StatusCode::NOT_FOUND)
        }
    }
}
//
//#[get("/api/sign_request", format = "application/json")]
//fn sign_request(mut cookies: Cookies, state: State<U2fClient>) -> Json<U2fSignRequest> {
//    let challenge = state.u2f.generate_challenge().unwrap();
//    let challenge_str = serde_json::to_string(&challenge);
//
//    // Only for this demo we will keep the challenge in a private (encrypted) cookie
//    cookies.add_private(Cookie::new("challenge", challenge_str.unwrap()));
//
//    let signed_request = state.u2f.sign_request(challenge, REGISTRATIONS.lock().unwrap().clone());
//
//    return Json(signed_request);
//}
//
//#[post("/api/sign_response", format = "application/json", data = "<response>")]
//fn sign_response(mut cookies: Cookies, response: Json<SignResponse>, state: State<U2fClient>) -> Result<JsonValue, NotFound<String>> {
//    let cookie = cookies.get_private("challenge");
//    if let Some(ref cookie) = cookie {
//        let challenge: Challenge = serde_json::from_str(cookie.value()).unwrap();
//
//        let registrations = REGISTRATIONS.lock().unwrap().clone();
//        let sign_resp = response.into_inner();
//
//        let mut _counter: u32 = 0;
//        for registration in registrations {
//            let response = state.u2f.sign_response(challenge.clone(), registration, sign_resp.clone(), _counter);
//            match response {
//                Ok(new_counter) =>  {
//                    _counter = new_counter;
//                    return Ok(json!({"status": "success"}));
//                },
//                Err(_e) => {
//                    break;
//                }
//            }
//        }
//        return Err(NotFound(format!("error verifying response")));
//    } else {
//        return Err(NotFound(format!("Not able to recover challenge")));
//    }
//}

