use std::collections::HashMap;
use std::any::{Any, TypeId};
use std::sync::{Arc, Mutex, RwLock};
use crate::misc::config::{Config, load_conf};
use crate::misc::health::HealthState;

pub struct Services {
    services : HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
    named_services : HashMap<String, Arc<dyn Any + Send + Sync>>,
}

pub type ServicesShared = Arc<RwLock<Services>>;

impl Services {
    pub fn new() -> Self {
        Services {services: HashMap::new(), named_services: HashMap::new()}
    }

    pub fn new_shared() -> ServicesShared {
        Arc::new(RwLock::new(Services {services: HashMap::new(), named_services: HashMap::new()}))
    }

    pub fn add_service<A : 'static + Any + Send + Sync>(&mut self, service : A) {
        self.services.insert(service.type_id(), Arc::new(service));
    }

    pub fn add_named_service<A : 'static + Any + Send + Sync>(&mut self, service : A, name : &str) {
        self.named_services.insert(name.to_owned(), Arc::new(service));
    }

    pub fn get_service<A : Any + Send + Sync>(&self) -> Option<Arc<A>> {
        if let Some(b) = self.services.get(&TypeId::of::<A>()) {
            return Some((*b).clone().downcast::<A>().unwrap());
        }
        None
    }

    pub fn get_service_clone<A : Any + Send + Sync + Clone>(&self) -> Option<A> {
        if let Some(b) = self.services.get(&TypeId::of::<A>()) {
            return Some((*b).clone().downcast::<A>().unwrap().as_ref().clone());
        }
        None
    }

    pub fn get_named_service<A : Any + Send + Sync>(&self, name : &str) -> Option<Arc<A>> {
        if let Some(b) = self.named_services.get(name) {
            return Some((*b).clone().downcast::<A>().unwrap());
        }
        None
    }

    pub fn get_named_service_clone<A : Any + Send + Sync + Clone>(&self, name : &str) -> Option<A> {
        if let Some(b) = self.named_services.get(name) {
            return Some((*b).clone().downcast::<A>().unwrap().as_ref().clone());

        }
        None
    }
}

pub fn init() -> ServicesShared {
    let ss = Services::new_shared();

    {
        let mut lock = ss.write().unwrap();
        lock.add_service(HealthState::new());
        lock.add_service(load_conf().unwrap());
    }

    ss
}