const argon2 = require('argon2');
const Validator = require('jsonschema').Validator;
const v = new Validator();
const xorInplace = require('buffer-xor/inplace');

const createPromiseRequestSchema = {
    "type": "object",
    "properties": {
        "server_id": {
            "type": "string",
            "required": true
        },
        "trustkey_ts": {
            "type": "integer",
            "required": true
        },
        "n_bytes": {
            "type": "integer",
            "required": true
        },
        "time_cost": {
            "type": "integer"
        },
        "memory_cost": {
            "type": "integer"
        },
        "parallelism": {
            "type": "integer"
        }
    }
};

const resolvePromiseRequestSchema = {
    "type": "object",
    "properties": {
        "server_id": {
            "type": "string",
            "required": true
        },
        "trustkey_ts": {
            "type": "integer",
            "required": true
        },
        "time_cost": {
            "type": "integer"
        },
        "memory_cost": {
            "type": "integer"
        },
        "parallelism": {
            "type": "integer"
        }
    }
};

const errorCodes = require('./errorCodes');

class Argon2dTrustkeyPromiseService {
    constructor(imports) {
        this.core = imports.core;
        this.rng = imports.rng;
        this.name = "trustkey_argon2d";
    }

    createPromise(request, callback) {
        //Recheck promise params and generate seed

        const vRes = v.validate(request, createPromiseRequestSchema);

        let response = { };

        const respondWithError = (ec) => {
            response.success = false;
            response.error_code = ec;
            response.error = errorCodes[ec];

            callback(response);
        };

        if(vRes.errors.length) {
            response.validation_errors = vRes.errors;
            return respondWithError(1);
        }

        let supervisor = this.core.getSupervisorByServerId(request.server_id);

        if(!supervisor.success || !supervisor.result.connected)
            return respondWithError(2);

        supervisor = supervisor.result;

        if((request.trustkey_ts % supervisor.roundTime) !== 0)
            return respondWithError(3);

        request.seed = this.rng.generate(request.n_bytes);

        delete request.n_bytes;

        response.success = true;
        response.result = request;

        callback(response);
    }

    resolvePromise(request, callback) {
        const vRes = v.validate(request, resolvePromiseRequestSchema);

        let response = {};

        const respondWithError = (ec) => {
            response.success = false;
            response.error_code = ec;
            response.error = errorCodes[ec];

            callback(response);
        };

        if(vRes.errors.length) {
            response.validation_errors = vRes.errors;
            return respondWithError(1);
        }

        let seedBytes = request.seed;

        if(typeof (seedBytes) === 'string')
            seedBytes = Buffer.from(seedBytes, 'base64');

        if(!Buffer.isBuffer(seedBytes))
            return respondWithError(7);

        let supervisor = this.core.getSupervisorByServerId(request.server_id);

        if(!supervisor.success)
            return respondWithError(2);

        supervisor = supervisor.result;

        supervisor.trustkeysCollection.findOne({ts: request.trustkey_ts}, (err, res) => {
            if(err) {
                response.db_error = err;
                return respondWithError(4);
            }

            if(!res) {
                return respondWithError(6);
            }

            if(!res.is_trusted) {
                response.trustkey = res;
                return respondWithError(5);
            }

            let options = {
                type: argon2.argon2d,
                raw: true,
                salt: new Buffer(res.trustkey, "hex")
            };

            if(request.time_cost)
                options.timeCost = request.time_cost;

            if(request.memory_cost)
                options.memoryCost = request.memory_cost;

            if(request.parallelism)
                options.parallelism = request.parallelism;

            options.hashLength = seedBytes.length;

            argon2.hash(res.inputs.buffer, options).then(function (res) {
                const bytes = xorInplace(seedBytes, res);

                callback({
                    success: true,
                    result: bytes
                });
            });
        });
    }

}

module.exports = function setup(options, imports, register) {
    const alg = new Argon2dTrustkeyPromiseService(imports);

    imports.promise.postAlgorithm(alg);
    register(null, {
        trustkey_argon2d: alg
    });
};