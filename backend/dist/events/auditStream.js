"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditStream = void 0;
const events_1 = require("events");
class AuditStream extends events_1.EventEmitter {
    emitLog(event) {
        this.emit("log", event);
    }
    onLog(handler) {
        this.on("log", handler);
        return () => this.off("log", handler);
    }
}
exports.auditStream = new AuditStream();
//# sourceMappingURL=auditStream.js.map