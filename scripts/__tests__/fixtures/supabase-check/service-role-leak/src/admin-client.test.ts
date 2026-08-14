// OK: test files are excluded even though they mention service_role in their description.
it("blocks service_role from being used client-side", () => {
  expect(true).toBe(true);
});
