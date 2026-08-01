<?php

declare(strict_types=1);

namespace Sentinel;

/**
 * Raised on any Sentinel API or transport failure.
 *
 * Mirrors SentinelError in the Node and Python SDKs: the HTTP status and the
 * decoded error body are attached when the failure came from the API rather
 * than from the network.
 */
class SentinelException extends \RuntimeException
{
    /** @var int|null HTTP status, or null for transport-level failures. */
    private $status;

    /** @var array<string,mixed> Decoded error body, empty on transport failure. */
    private $body;

    /**
     * @param array<string,mixed>|null $body
     */
    public function __construct(string $message, ?int $status = null, ?array $body = null)
    {
        parent::__construct($message);
        $this->status = $status;
        $this->body = $body ?? [];
    }

    public function getStatus(): ?int
    {
        return $this->status;
    }

    /**
     * @return array<string,mixed>
     */
    public function getBody(): array
    {
        return $this->body;
    }
}
