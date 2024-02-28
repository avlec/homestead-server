#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("DATABASE_URL").map_err(|_| sqlx::Error::PoolClosed)?)
        .await?;

    warp::serve(crate::routes::api(pool))
        .run(([0, 0, 0, 0], (1234)))
        .await;
    Ok(())
}

mod models {
    use serde::*;

    #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Value {
        Signed(i32),
        Unsigned(u32),
        Real(f32),
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Resource {
        pub what: String,
        pub value: Value,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct ContextResource {
        pub context: String,
        pub resource: Resource,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct HardwareAddress(Vec<u8>);

    impl std::fmt::Display for HardwareAddress {
        fn fmt(&self, f: &mut __private::Formatter<'_>) -> std::fmt::Result {
            self.0
                .iter()
                .map(|&v| v.to_string())
                .fold(String::new(), |a, b| {
                    if a.len() == 0 {
                        a + &b
                    } else {
                        a + ":" + &b
                    }
                })
                .fmt(f)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Capabilities {
        pub produces: Vec<String>, // list of names
        pub consumes: Vec<String>, // list of names
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Device {
        pub hwaddr: HardwareAddress,
        pub capabilities: Capabilities,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct DevicePut {
        pub hwaddr: HardwareAddress,
        pub resources: Vec<Resource>,
    }
}

mod routes {
    use crate::*;
    use warp::Filter;

    pub fn api(
        pool: sqlx::SqlitePool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = std::convert::Infallible> + Clone {
        let frontend = frontend_api();
        let device = device_api(&pool);
        let user = user_api(&pool);
        let favicon = warp::path!("favicon.ico").and(warp::fs::file("static/favicon.ico"));
        frontend
            .or(device)
            .or(user)
            .or(favicon)
            .recover(handle_rejection)
    }

    fn frontend_api() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let config = warp::get()
            .and(warp::path("config"))
            .and(warp::path::end())
            .and_then(frontend_config);
        config
    }

    #[derive(askama::Template)]
    #[template(path = "config.html")]
    struct ConfigTemplate;

    async fn frontend_config() -> Result<impl warp::Reply, warp::Rejection> {
        Ok(ConfigTemplate {})
    }

    fn user_api(
        pool: &sqlx::SqlitePool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let prefix = warp::get().and(warp::path!("v1" / "config" / ..));

        let device = warp::path!(String).and_then(query_device_config);
        let produces = warp::path!("produces" / String)
            .and(with_db(pool.clone()))
            .and_then(query_device_produces);
        let consumes = warp::path!("consumes" / String)
            .and(with_db(pool.clone()))
            .and_then(query_device_consumes);
        let list = warp::path::end()
            .and(with_db(pool.clone()))
            .and_then(query_config);

        prefix.and(produces.or(consumes).or(device).or(list))
    }

    #[derive(askama::Template)]
    #[template(path = "device_table.html")]
    struct DeviceTable {
        devices: Vec<(String, String)>,
    }

    /**
     *  Builds an HTML table of devices, with references to their configuration.
     *  */
    async fn query_config(pool: sqlx::SqlitePool) -> Result<impl warp::Reply, warp::Rejection> {
        let query: Vec<(String, String)> = sqlx::query!(r#"SELECT id, label FROM devices"#)
            .fetch_all(&pool)
            .await
            .map_err(db::towarperr)?
            .iter()
            .map(|result| {
                (
                    result.id.clone(),
                    match &result.label {
                        Some(v) => v.clone(),
                        None => "unconfigured device".into(),
                    },
                )
            })
            .collect();

        Ok(DeviceTable { devices: query })
    }

    async fn query_device_produces(
        hwaddr_str: String,
        pool: sqlx::SqlitePool,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let result = sqlx::query!(
            r#"SELECT what, val as `val!: f32` FROM provisions WHERE provisions.deviceID = ?"#,
            hwaddr_str
        )
        .fetch_all(&pool)
        .await
        .map_err(db::towarperr)?;

        let mut body = String::new();
        body += "<p>Produces:</p><ul>";
        for provision in result.iter() {
            let prov_str = format!(
                r#"<li>{} current val is {}</li>"#,
                provision.what, provision.val
            );
            body += &prov_str;
        }
        body += "</ul>";
        Ok(warp::reply::html(body))
    }

    async fn query_device_consumes(
        hwaddr_str: String,
        pool: sqlx::SqlitePool,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let result = sqlx::query!(
            r#"SELECT what, producingDeviceID, produces FROM consumptions WHERE consumptions.consumingDeviceID = ?"#,
            hwaddr_str
        )
        .fetch_all(&pool)
        .await
        .map_err(db::towarperr)?;

        let mut body = String::new();
        body += "<p>Consumes:</p><ul>";
        for consumption in result.iter() {
            let producer = match &consumption.producingDeviceID {
                Some(v) => v.clone(),
                None => "noone".into(),
            };
            let product = match &consumption.produces {
                Some(v) => v.clone(),
                None => "nothing".into(),
            };
            let prov_str = format!(
                r#"<li><label>{consumer}</label> uses {product} from {producer}
                "#,
                consumer = consumption.what
            );
            body += &prov_str;
        }
        body += "</ul>";

        Ok(warp::reply::html(body))
    }

    async fn query_device_config(hwaddr_str: String) -> Result<impl warp::Reply, warp::Rejection> {
        Ok(warp::reply::html(format!(
            r#"
            <div hx-get="/v1/config/produces/{hwaddr_str}" hx-trigger="load">Produces Loading...</div>
            <div hx-get="/v1/config/consumes/{hwaddr_str}" hx-trigger="load">Consumes Loading...</div>
            "#
        )))
    }

    fn device_api(
        pool: &sqlx::SqlitePool,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        let path = warp::path!("v1" / "device");

        let post_device = warp::post()
            .and(path)
            .and(warp::body::json())
            .and(with_db(pool.clone()))
            .and_then(device_register);

        let get_device = warp::get()
            .and(path)
            .and(warp::body::json())
            .and(with_db(pool.clone()))
            .and_then(get_device);

        let set_device = warp::put()
            .and(path)
            .and(warp::body::json())
            .and(with_db(pool.clone()))
            .and_then(put_device);

        post_device.or(get_device).or(set_device)
    }

    fn with_db(
        db: sqlx::Pool<sqlx::sqlite::Sqlite>,
    ) -> impl warp::Filter<
        Extract = (sqlx::Pool<sqlx::sqlite::Sqlite>,),
        Error = std::convert::Infallible,
    > + Clone {
        warp::any().map(move || db.clone())
    }

    #[derive(serde::Serialize)]
    struct ErrorMessage {
        code: u16,
        message: String,
    }

    async fn handle_rejection(
        err: warp::Rejection,
    ) -> Result<impl warp::Reply, std::convert::Infallible> {
        use warp::http::StatusCode;
        let code = if err.is_not_found() {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_REQUEST
        };
        let json = warp::reply::json(&ErrorMessage {
            code: code.as_u16(),
            message: if err.is_not_found() {
                "not found".to_string()
            } else if let Some(e) = err.find::<db::DatabaseError>() {
                format!("database error {}", e.to_string())
            } else {
                eprintln!("unhandled rejection: {:?}", err);
                "some other error".to_string()
            }
            .into(),
        });
        Ok(warp::reply::with_status(json, code))
    }

    /**
     *  Device registration takes in essentially a hardware address, and
     *  the devices capabilities. Registers that device has those capabilities
     *  which the server then leaves up to the user to configure which of
     *  the capabilities are to be utilized.
     *  */
    async fn device_register(
        dev: models::Device,
        pool: sqlx::SqlitePool,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        db::transaction!(pool, |tx| add_device_and_capabilities(&dev, tx));
        Ok(warp::reply::json(&dev.hwaddr))
    }

    async fn add_device_and_capabilities(
        dev: &models::Device,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> Result<(), sqlx::Error> {
        let hwaddr = dev.hwaddr.to_string();
        // insert the device if it can, otherwise who cares
        let _ = sqlx::query!(
            r#"INSERT INTO devices
            (id, label) VALUES (?, 'unconfigured device')"#,
            hwaddr
        )
        .execute(&mut **tx)
        .await;

        for pcap in dev.capabilities.produces.iter() {
            sqlx::query!(
                r#"INSERT INTO provisions
                (deviceID, what, val) VALUES (?, ?, 0.0)"#,
                hwaddr,
                pcap
            )
            .execute(&mut **tx)
            .await?;
        }

        for ccap in dev.capabilities.consumes.iter() {
            sqlx::query!(
                "INSERT INTO consumptions
                (consumingDeviceID, what) VALUES (?, ?)",
                hwaddr,
                ccap
            )
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    /**
     *  The goal with this service is to read the device capabilities from the database and to then turn on capabilities by
     *  */
    async fn configure_device(
        hwaddr: models::HardwareAddress,
        produces: Vec<String>,
        consumes: Vec<String>,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> Result<(), sqlx::Error> {
        let hwaddr = hwaddr.to_string();

        for product in produces.iter() {
            sqlx::query!(
                "INSERT INTO provisions
                (deviceID, what) VALUES (?, ?)",
                hwaddr,
                product,
            )
            .execute(&mut **tx)
            .await?;
        }

        for consume in consumes.iter() {
            sqlx::query!(
                r#"INSERT INTO provisions
                (deviceID, what) VALUES (?, ?)"#,
                hwaddr,
                consume
            )
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    /**
     *  This is when the device checks in with the server. This will
     *  report values the server had previously configured the device
     *  to use. The server will reply with a response of the values the
     *  device consumes as mapped to the available consumption points as
     *  well as if changed a new device production list (which will apply
     *  on the next check in.)
     *  */
    async fn put_device(
        dev_put: models::DevicePut,
        pool: sqlx::Pool<sqlx::sqlite::Sqlite>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        // update the database with new values from the device
        db::transaction!(pool, |tx| update_provisions(dev_put, tx));
        Ok(warp::reply::json(&()))
    }

    async fn update_provisions(
        dev_put: models::DevicePut,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> Result<(), sqlx::Error> {
        let hwaddr = dev_put.hwaddr.to_string();

        for resource in dev_put.resources.iter() {
            // TODO handle values other than real properly...
            let value = match resource.value {
                models::Value::Real(v) => v,
                models::Value::Signed(v) => v as f32,
                models::Value::Unsigned(v) => v as f32,
            };
            sqlx::query!(
                r#"UPDATE provisions
                SET val = ?
                WHERE deviceID = ? AND what = ?"#,
                value,
                hwaddr,
                resource.what
            )
            .execute(&mut **tx)
            .await?;
        }

        Ok(())
    }

    async fn get_device(
        hwaddr: models::HardwareAddress,
        pool: sqlx::SqlitePool,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        // update the device with new values from the database
        let hwaddr = hwaddr.to_string();
        let providers = sqlx::query!(
            r#"SELECT consumptions.what as consume, provisions.what as produce, provisions.val as `val!: f32`
            FROM consumptions
            JOIN provisions
            ON consumptions.producingDeviceID = provisions.deviceID
            AND consumptions.produces = provisions.what
            AND consumptions.consumingDeviceID = ?
            AND provisions.val IS NOT NULL
            "#,
            hwaddr
        )
        .fetch_all(&pool)
        .await
        .map_err(db::towarperr)?;

        let sub: Vec<models::ContextResource> = providers
            .iter()
            .map(|v| models::ContextResource {
                context: v.consume.clone(),
                resource: models::Resource {
                    what: v.produce.clone(),
                    value: models::Value::Real(v.val),
                },
            })
            .collect();

        Ok(warp::reply::json(&sub))
    }
}

mod db {
    #[derive(Debug)]
    pub struct DatabaseError(sqlx::Error);

    impl warp::reject::Reject for DatabaseError {}

    impl ToString for DatabaseError {
        fn to_string(&self) -> String {
            self.0.to_string()
        }
    }

    // probably have to clean these up...
    pub fn towarperr(err: sqlx::Error) -> warp::Rejection {
        warp::reject::custom(DatabaseError(err))
    }

    macro_rules! transaction {
        ($pool:expr, $closure:expr) => {
            let mut tx = $pool.begin().await.map_err(db::towarperr)?;
            $closure(&mut tx).await.map_err(db::towarperr)?;
            tx.commit().await.map_err(db::towarperr)?;
        };
    }

    pub(crate) use transaction;
}
