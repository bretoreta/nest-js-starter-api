import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { BlogModule } from './blog/blog.module';
import { DatabaseModule } from './database/database.module';

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true }), AuthModule, UserModule, BlogModule, DatabaseModule],
})
export class AppModule {}
