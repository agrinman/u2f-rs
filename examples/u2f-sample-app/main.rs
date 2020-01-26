#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_derive;

mod util;
use self::util::*;

use u2f::protocol::*;
use u2f::messages::*;
use u2f::register::*;

use std::sync::Mutex;

use warp::{Filter, Reply};

static APP_ID : &'static str = "https://localhost:30443";

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    sodiumoxide::init().unwrap();

    let index = warp::get().and(warp::path::end()).map(index);

    let register = warp::get()
        .and(warp::path("api"))
        .and(warp::path("register_request"))
        .map(register_request);

    let reg_done = warp::post()
        .and(warp::path("api"))
        .and(warp::path("register_response"))
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

 }

fn index() -> impl Reply {
    warp::reply::html(include_str!("static/index.html"))
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
        Err(_) => {
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

