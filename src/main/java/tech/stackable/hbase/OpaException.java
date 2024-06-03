package tech.stackable.hbase;

import java.net.URI;
import java.net.http.HttpResponse;

public abstract class OpaException extends RuntimeException {

  protected OpaException(String message, Throwable cause) {
    super(message, cause);
  }

  public static final class UriMissing extends OpaException {
    public UriMissing(String configuration) {
      super(
          "No Open Policy Agent URI provided (must be set in the configuration \""
              + configuration
              + "\")",
          null);
    }
  }

  public static final class UriInvalid extends OpaException {
    public UriInvalid(URI uri, Throwable cause) {
      super(
          "Open Policy Agent URI is invalid (see configuration property \""
              + OpenPolicyAgentAccessController.OPA_POLICY_URL_PROP
              + "\"): "
              + uri,
          cause);
    }
  }

  public static final class EndPointNotFound extends OpaException {
    public EndPointNotFound(String url) {
      super(
          "Open Policy Agent URI is unreachable (see configuration property \""
              + OpenPolicyAgentAccessController.OPA_POLICY_URL_PROP
              + "\"): "
              + url,
          null);
    }
  }

  public static final class QueryFailed extends OpaException {
    public QueryFailed(Throwable cause) {
      super("Failed to query OPA backend", cause);
    }
  }

  public static final class OpaServerError extends OpaException {
    public <T> OpaServerError(String query, HttpResponse<T> response) {
      super(
          "OPA server returned status "
              + response.statusCode()
              + " when processing query "
              + query
              + ": "
              + response.body(),
          null);
    }
  }

  public static final class SerializeFailed extends OpaException {
    public SerializeFailed(Throwable cause) {
      super("Failed to serialize OPA query context", cause);
    }
  }

  public static final class DeserializeFailed extends OpaException {
    public DeserializeFailed(Throwable cause) {
      super("Failed to deserialize OPA policy response", cause);
    }
  }
}
