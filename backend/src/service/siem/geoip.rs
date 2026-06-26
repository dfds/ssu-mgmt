use std::net::IpAddr;
use std::sync::Arc;

use log::{info, warn};
use maxminddb::{geoip2, Reader};

#[derive(Clone, Default)]
pub struct GeoIp {
    reader: Option<Arc<Reader<Vec<u8>>>>,
}

/// A resolved geo point: coordinates (for distance maths) plus the human label.
#[derive(Clone, Debug)]
pub struct GeoPoint {
    pub lat: f64,
    pub lon: f64,
    pub label: String,
}

impl GeoIp {
    /// Load the GeoLite2 City DB from `db_path`. An empty path or any read error
    /// yields a disabled (no-op) instance — geo enrichment degrades gracefully.
    pub fn load(db_path: &str) -> Self {
        if db_path.is_empty() {
            info!("geoip: no db_path configured — session location disabled");
            return Self::default();
        }
        match Reader::open_readfile(db_path) {
            Ok(r) => {
                info!("geoip: loaded GeoLite2 db from {}", db_path);
                Self { reader: Some(Arc::new(r)) }
            }
            Err(e) => {
                warn!("geoip: failed to open {}: {} — session location disabled", db_path, e);
                Self::default()
            }
        }
    }

    pub fn enabled(&self) -> bool {
        self.reader.is_some()
    }

    /// Resolve an IP string to `"City, Country"` (or whichever parts are known).
    /// Returns `None` for an unparseable/private IP or when geo is disabled.
    pub fn lookup(&self, ip: &str) -> Option<String> {
        let reader = self.reader.as_ref()?;
        let addr: IpAddr = ip.parse().ok()?;
        let city: geoip2::City = reader.lookup(addr).ok()?;

        let city_name = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string());
        let country_name = city
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string());

        match (city_name, country_name) {
            (Some(c), Some(co)) => Some(format!("{}, {}", c, co)),
            (None, Some(co)) => Some(co),
            (Some(c), None) => Some(c),
            (None, None) => None,
        }
    }

    /// Resolve an IP to coordinates + label, for impossible-travel maths. Returns
    /// `None` for unparseable/private IPs, when geo is disabled, or when the DB has
    /// no coordinates for the IP.
    pub fn lookup_geo(&self, ip: &str) -> Option<GeoPoint> {
        let reader = self.reader.as_ref()?;
        let addr: IpAddr = ip.parse().ok()?;
        let city: geoip2::City = reader.lookup(addr).ok()?;

        let loc = city.location.as_ref()?;
        let lat = loc.latitude?;
        let lon = loc.longitude?;
        let label = self.lookup(ip).unwrap_or_else(|| ip.to_string());
        Some(GeoPoint { lat, lon, label })
    }
}

/// Great-circle distance between two points in kilometres (haversine).
pub fn haversine_km(a: &GeoPoint, b: &GeoPoint) -> f64 {
    const R: f64 = 6371.0;
    let (lat1, lat2) = (a.lat.to_radians(), b.lat.to_radians());
    let dlat = (b.lat - a.lat).to_radians();
    let dlon = (b.lon - a.lon).to_radians();
    let h = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * R * h.sqrt().asin()
}
