pub fn setup_metrics() {

    // chases
    // metrics::describe_counter!("chasescanner_chases_detected", "How many chases has been detected");
    // metrics::describe_counter!("chasescanner_chases_detected_by_source", "How many chases has been detected by source");
    // metrics::describe_gauge!("chasescanner_jobs_active", "How many jobs are currently active");
    // metrics::describe_gauge!("chasescanner_job_active", "Is {Job} running");
    // metrics::gauge!("chasescanner_jobs_active", 0.0);
}

pub fn metric_name(val : &str) -> String {
    format!("ssu_mgmt_{}", val)
}