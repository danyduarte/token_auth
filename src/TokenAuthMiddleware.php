<?php
/**
 * @file
 * Contains \Drupal\token_auth\TokenAuthMiddleware.
 */

namespace Drupal\token_auth;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Drupal\user\Entity\User;
use Drupal\Core\StringTranslation\StringTranslationTrait;


/**
 * Token Auth Middleware.
 *
 * @package Drupal\token_auth
 */
class TokenAuthMiddleware implements HttpKernelInterface {

  use StringTranslationTrait;

  /**
   * The wrapped HTTP kernel.
   *
   * @var \Symfony\Component\HttpKernel\HttpKernelInterface
   */
  protected $httpKernel;

  /**
   * Constructs Rate Limiter Middleware.
   *
   * @param \Symfony\Component\HttpKernel\HttpKernelInterface $app
   *   The wrapper HTTP kernel.
   */
  public function __construct(HttpKernelInterface $httpKernel) {
    $this->httpKernel = $httpKernel;
  }

  /**
   * {@inheritdoc}
   */
  public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = TRUE) {

    if (!(\Drupal::currentUser()->isAnonymous())) {
      $request_token = $request->query->get('authtoken');
      $query = \Drupal::service('entity.query')
        ->get('user')
        ->condition('field_auth_token', $request_token);
      $entity_id = $query->execute();
      if (empty($entity_id)) {
        return new Response($this->t('Access Denied'), 403);
      }
      else {
        $entity_id = array_pop($entity_id);
        $account = User::load($entity_id);
        user_login_finalize($account);
      }
    }

    return $this->httpKernel->handle($request, $type, $catch);
  }
}
