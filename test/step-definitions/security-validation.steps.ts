import { Given, Then } from '@cucumber/cucumber';

Given('the manual test case {string} is available', function (this: any, _id: string) {
  return true;
});

Then('the automation harness validates the scenario', function (this: any) {
  return true;
});
