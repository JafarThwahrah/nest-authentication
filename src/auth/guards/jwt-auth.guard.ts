import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
// by adding the local here we will automatically invoke the local strategy, but we dont use this class we call the AuthGuard direcrly in the auth service
export class JwtAuthGuard extends AuthGuard('jwt') {}
