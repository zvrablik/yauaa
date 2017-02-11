/*
 * Yet Another UserAgent Analyzer
 * Copyright (C) 2013-2017 Niels Basjes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.basjes.parse.useragent.analyze.treewalker.steps.lookup;

import nl.basjes.parse.useragent.analyze.treewalker.steps.Step;
import org.antlr.v4.runtime.tree.ParseTree;

import java.util.Map;

public class StepLookup extends Step {

    private final String lookupName;
    private final Map<String, String> lookup;
    private final String defaultValue;

    public StepLookup(String lookupName, Map<String, String> lookup, String defaultValue) {
        this.lookupName = lookupName;
        this.lookup = lookup;
        this.defaultValue = defaultValue;
    }

    @Override
    public String walk(ParseTree tree, String value) {
        String input = getActualValue(tree, value);

        if (input == null) {
            if (defaultValue == null) {
                if (verbose) {
                    LOG.info("{} Lookup: {}[{}] => Input null", logprefix, lookupName, input);
                }
                return null;
            } else {
                if (verbose) {
                    LOG.info("{} Lookup: {}[{}] => Input null --> USE DEFAULT:{}", logprefix, lookupName, input, defaultValue);
                }
                return walkNextStep(tree, defaultValue);
            }
        }

        String result = lookup.get(input.toLowerCase());

        if (result == null) {
            if (defaultValue == null) {
                if (verbose) {
                    LOG.info("{} Lookup: {}[{}] => null", logprefix, lookupName, input);
                }
                return null;
            } else {
                if (verbose) {
                    LOG.info("{} Lookup: {}[{}] => USE DEFAULT:{}", logprefix, lookupName, input, defaultValue);
                }
                return walkNextStep(tree, defaultValue);
            }
        }

        if (verbose) {
            LOG.info("{} Lookup: {}[{}] => Lookup:{}", logprefix, lookupName, input, result);
        }
        return walkNextStep(tree, result);
    }

    @Override
    public String toString() {
        return "Lookup(@" + lookupName + " ; default="+defaultValue+")";
    }

}
