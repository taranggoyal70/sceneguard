export const ACCOUNT_ROLES = Object.freeze(["owner", "member"]);

export function roleAllows(actualRole, allowedRoles) {
  return Array.isArray(allowedRoles) && allowedRoles.includes(actualRole);
}

export function requireRole(...allowedRoles) {
  return (request, response, next) => {
    if (!roleAllows(request.auth?.role, allowedRoles)) {
      return response.status(403).json({ error: "You do not have permission to perform this action." });
    }
    next();
  };
}
