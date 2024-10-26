import http from 'k6/http';
import { check } from 'k6';

export const options = {
    vus: 3,
    duration: '4s',
};

export default function () {

    const reqJsonPath1 = {
        method: 'POST',
        url: 'http://localhost:8181/',
        body: JSON.stringify({ "http_request": { "headers": { "x-source": "client1", "x-path": "/json_1/1", "x-method": "get" } } }),
        params: {
            headers: {
                'Content-Type': 'application/json',
            },
        }
    };

    const reqJsonPath2 = {
        method: 'POST',
        url: 'http://localhost:8181/',
        body: JSON.stringify({ "http_request": { "headers": { "x-source": "client1", "x-path": "/json_1/1", "x-method": "get" } } }),
        params: {
            headers: {
                'Content-Type': 'application/json',
            },
        }
    };

    const reqJsonPath3 = {
        method: 'POST',
        url: 'http://localhost:8181/',
        body: JSON.stringify({ "http_request": { "headers": { "x-source": "client1", "x-path": "/json_1/1", "x-method": "get" } } }),
        params: {
            headers: {
                'Content-Type': 'application/json',
            },
        }
    };

    const responses = http.batch([
        reqJsonPath1, reqJsonPath2, reqJsonPath3
    ]);

    check(responses[0], {
        'main page status was 200': (res) => res.status === 200,
    });

    check(responses[1], {
        'main page status was 200': (res) => res.status === 200,
    });

    check(responses[2], {
        'main page status was 200': (res) => res.status === 200,
    });
}