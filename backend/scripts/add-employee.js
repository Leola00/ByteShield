/**
 * Add an employee to public.analysts (email + password).
 *
 * Usage:
 *   node scripts/add-employee.js email@company.com TheirPassword "Full Name"
 */
require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });
const authService = require("../services/authService");

async function main() {
  const email = process.env.EMPLOYEE_EMAIL || process.argv[2];
  const password = process.env.EMPLOYEE_PASSWORD || process.argv[3];
  const fullName = process.env.EMPLOYEE_NAME || process.argv[4] || "";
  const role = process.env.EMPLOYEE_ROLE || process.argv[5] || "Fraud Analyst";
  const team = process.env.EMPLOYEE_TEAM || process.argv[6] || "Fraud Team";

  if (!email || !password) {
    console.error(
      'Usage: node scripts/add-employee.js email@company.com Password "Full Name"',
    );
    process.exit(1);
  }

  const analyst = await authService.createEmployee({
    email,
    password,
    fullName,
    role,
    team,
  });

  console.log("Employee created in analysts table. They can sign in now.");
  console.log(JSON.stringify(analyst, null, 2));
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
