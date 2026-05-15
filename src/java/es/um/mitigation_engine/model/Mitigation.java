/*
 * Copyright (C) 2025, 2026 Ekam Puri Nieto (UMU), Antonio Skarmeta
 * Gomez (UMU), Jorge Bernal Bernabe (UMU).
 *
 * See LICENSE file in the project root for details.
 */

package es.um.mitigation_engine.model;

import org.optaplanner.core.api.domain.entity.PlanningEntity;
import org.optaplanner.core.api.domain.variable.PlanningVariable;

@PlanningEntity
public class Mitigation {

    @PlanningVariable(nullable = true, valueRangeProviderRefs = "workflows")
    private WorkflowInstance workflow;

    @PlanningVariable(nullable = true, valueRangeProviderRefs = "alerts")
    private Alert alert;

    public WorkflowInstance getWorkflow() {
        return workflow;
    }

    public boolean invalid() {
        if (workflow == null)
            return true;

        if (alert == null)
            return true;

        if (!workflow.getSignature().applicableTo(alert))
            return true;

        if (!workflow.valid())
            return true;

        return false;
    }

    public Alert getAlert() {
        return alert;
    }
}
