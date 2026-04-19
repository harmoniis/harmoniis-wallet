//! IndexedDB persistence for HarmoniiStore state (WASM only).
//!
//! Same pattern as webylib::wallet::idb — async load/save over sync MemHarmoniiStore.
//! One database per network, keyed by wallet label (e.g. "master", "webcash:main").

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{IdbDatabase, IdbTransactionMode};

use crate::error::{Error, Result};

const DB_VERSION: u32 = 1;
const STORE_NAME: &str = "harmoniis_state";

fn db_name(network: &str) -> String {
    format!("harmoniis-wallet-{}", network)
}

async fn await_request(req: &web_sys::IdbRequest) -> std::result::Result<(), JsValue> {
    let (tx, rx) = futures_channel::oneshot::channel::<std::result::Result<(), JsValue>>();
    let tx = std::rc::Rc::new(std::cell::RefCell::new(Some(tx)));

    let tx2 = tx.clone();
    let on_success = Closure::once(move |_: web_sys::Event| {
        if let Some(tx) = tx2.borrow_mut().take() { let _ = tx.send(Ok(())); }
    });
    let on_error = Closure::once(move |e: web_sys::Event| {
        if let Some(tx) = tx.borrow_mut().take() { let _ = tx.send(Err(e.into())); }
    });
    req.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
    req.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    on_success.forget();
    on_error.forget();
    rx.await.unwrap_or(Err(JsValue::from_str("channel dropped")))
}

async fn open_db(network: &str) -> Result<IdbDatabase> {
    let window = web_sys::window().ok_or_else(|| Error::Other(anyhow::anyhow!("no window")))?;
    let factory = window
        .indexed_db()
        .map_err(|_| Error::Other(anyhow::anyhow!("IndexedDB not available")))?
        .ok_or_else(|| Error::Other(anyhow::anyhow!("IndexedDB not available")))?;

    let open_req = factory
        .open_with_u32(&db_name(network), DB_VERSION)
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB open: {:?}", e)))?;

    let on_upgrade = Closure::once(move |event: web_sys::IdbVersionChangeEvent| {
        let req: web_sys::IdbOpenDbRequest = event.target().unwrap().dyn_into().unwrap();
        let db: IdbDatabase = req.result().unwrap().dyn_into().unwrap();
        if !db.object_store_names().contains(STORE_NAME) {
            db.create_object_store(STORE_NAME).unwrap();
        }
    });
    open_req.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
    on_upgrade.forget();

    await_request(open_req.as_ref()).await
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB open await: {:?}", e)))?;
    open_req.result()
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB open result: {:?}", e)))?
        .dyn_into::<IdbDatabase>()
        .map_err(|_| Error::Other(anyhow::anyhow!("IDB: result is not a database")))
}

pub async fn load(network: &str, key: &str) -> Result<Option<String>> {
    let db = open_db(network).await?;
    let tx = db.transaction_with_str_and_mode(STORE_NAME, IdbTransactionMode::Readonly)
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB tx: {:?}", e)))?;
    let store = tx.object_store(STORE_NAME)
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB store: {:?}", e)))?;
    let req = store.get(&JsValue::from_str(key))
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB get: {:?}", e)))?;

    await_request(&req).await
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB get await: {:?}", e)))?;

    let result = req.result()
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB get result: {:?}", e)))?;
    if result.is_undefined() || result.is_null() {
        Ok(None)
    } else {
        result.as_string().map(Some)
            .ok_or_else(|| Error::Other(anyhow::anyhow!("IDB: value is not a string")))
    }
}

pub async fn save(network: &str, key: &str, json: &str) -> Result<()> {
    let db = open_db(network).await?;
    let tx = db.transaction_with_str_and_mode(STORE_NAME, IdbTransactionMode::Readwrite)
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB tx: {:?}", e)))?;
    let store = tx.object_store(STORE_NAME)
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB store: {:?}", e)))?;
    let req = store.put_with_key(&JsValue::from_str(json), &JsValue::from_str(key))
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB put: {:?}", e)))?;

    await_request(&req).await
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB put await: {:?}", e)))?;
    Ok(())
}

pub async fn delete(network: &str, key: &str) -> Result<()> {
    let db = open_db(network).await?;
    let tx = db.transaction_with_str_and_mode(STORE_NAME, IdbTransactionMode::Readwrite)
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB tx: {:?}", e)))?;
    let store = tx.object_store(STORE_NAME)
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB store: {:?}", e)))?;
    let req = store.delete(&JsValue::from_str(key))
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB delete: {:?}", e)))?;

    await_request(&req).await
        .map_err(|e| Error::Other(anyhow::anyhow!("IDB delete await: {:?}", e)))?;
    Ok(())
}
