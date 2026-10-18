package io.github.rmkrdev.entra.security.core.graph;

import java.util.List;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

/**
 * Reactive counterpart of {@link GroupMembershipResolver}, used by WebFlux resource servers to resolve a
 * user's groups on group overage without blocking the event loop.
 */
@FunctionalInterface
public interface ReactiveGroupMembershipResolver {

    /**
     * @param tenantId the {@code tid} of the token
     * @param objectId the user's {@code oid}
     * @return the user's groups; an error signal when the lookup fails
     */
    Mono<List<GroupMembership>> resolve(String tenantId, String objectId);

    /**
     * Adapts a blocking resolver by running it on {@link Schedulers#boundedElastic()}.
     */
    static ReactiveGroupMembershipResolver fromBlocking(GroupMembershipResolver resolver) {
        return fromBlocking(resolver, Schedulers.boundedElastic());
    }

    /**
     * Adapts a blocking resolver by running it on {@code scheduler}.
     */
    static ReactiveGroupMembershipResolver fromBlocking(GroupMembershipResolver resolver, Scheduler scheduler) {
        return (tenantId, objectId) -> Mono.fromCallable(() -> resolver.resolve(tenantId, objectId))
                .subscribeOn(scheduler);
    }
}
