export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export function passwordPolicyErrors(password) {
  const value = typeof password === "string" ? password : "";
  const errors = [];
  if (value.length < PASSWORD_MIN_LENGTH) errors.push(`Use at least ${PASSWORD_MIN_LENGTH} characters.`);
  if (value.length > PASSWORD_MAX_LENGTH) errors.push(`Use no more than ${PASSWORD_MAX_LENGTH} characters.`);
  if (!/[a-z]/.test(value)) errors.push("Add a lowercase letter.");
  if (!/[A-Z]/.test(value)) errors.push("Add an uppercase letter.");
  if (!/[0-9]/.test(value)) errors.push("Add a number.");
  if (!/[^A-Za-z0-9]/.test(value)) errors.push("Add a symbol.");
  return errors;
}

export function isStrongPassword(password) {
  return passwordPolicyErrors(password).length === 0;
}
