.PHONY: frontend backend build dev-backend dev-frontend clean

frontend:
	cd frontend && npm ci && npm run build

backend:
	cd backend && cargo build --release

build: frontend backend

dev-frontend:
	cd frontend && npm run dev

dev-backend:
	cd backend && cargo run

clean:
	rm -rf frontend/dist frontend/node_modules
	find backend/dist -mindepth 1 ! -name .gitkeep -delete
	cd backend && cargo clean
