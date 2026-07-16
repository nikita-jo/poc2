/**
 * Cucumber world bootstrap.
 *
 * Loaded via `require` from cucumber.js BEFORE any step-definition
 * file so the custom World is in place by the time Cucumber wires up
 * the scenario context. This file intentionally does not export
 * anything; its side-effect (setWorldConstructor) is the entire
 * purpose.
 */
import { setWorldConstructor } from '@cucumber/cucumber';
import { LabWorld } from './world';

setWorldConstructor(LabWorld);
