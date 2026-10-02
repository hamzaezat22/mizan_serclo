
function checkGranularPermission(session, actionType) {
    if (!session) return false;
    if (session.p || session.r === "admin" || (session.perms && session.perms === "ALL")) return true;
    const perms = String(session.perms || "").split(",");
    const requiredMap = {
        "SALE_INVOICE": "POS_SaveInvoice",
        "EDIT_INVOICE": "Sales_EditInvoice",
        "DELETE_INVOICE": "Sales_DeleteInvoice",
        "COLLECTION": "Collections_Add",
        "DELETE_COLLECTION": "Collections_Delete",
        "EXPENSE": "Expenses_Add",
        "DELETE_EXPENSE": "Expenses_Delete",
        "SETTLE_VEHICLE": "Vehicles_Settle",
        "LOAD_SUPPLY": "Vehicles_Add"
    };
    const req = requiredMap[actionType];
    return !req || perms.includes(req);
}
